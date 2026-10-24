package casserver

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sort"
	"time"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/shardformat"
)

// maxDedupAnswerChunks caps the chunk entries in one global-dedup answer:
// 65536 entries is about 3 MB on the wire and describes about 4 GB of
// content at the default 64 KB chunk. The client caches every answer as
// a shard file, so the bound keeps one query from pulling a whole repo's
// index; the xorb the chunk lives in always fits.
const maxDedupAnswerChunks = 1 << 16

// dedupAnswer builds the body of GET /v1/chunks/{prefix}/{hash} for a
// chunk the server knows: a shard whose xorb-info lists the xorb the
// chunk lives in first, then every other xorb of every file that
// references that xorb, in term order. No file entries: xet-core's own
// reference client (LocalClient::query_for_global_dedup_shard) answers
// with an xorb-only shard too, and the querying client uses only the
// chunk lookup.
//
// Why not just the shard that introduced the chunk, as before: an upload
// shard's xorb-info lists only the xorbs that upload created, so a chunk
// born in a two-chunk edit maps to a two-chunk shard. xet-core queries
// the first chunk of a file and then at most once per 256 chunks, so a
// second machine editing a file whose first chunk had been edited before
// got one answer covering two chunks and re-uploaded everything else,
// with the file's other xorbs on the server the whole time.
//
// Security: every answer is keyed with a fresh random 32-byte key and
// carries no file-reconstruction entries. Chunk hashes in the stored
// shards are the raw content hashes; serving them unkeyed let any caller
// holding one chunk learn the raw hashes of every other chunk in the
// matching xorbs (plus file hashes and reconstruction terms), enough to
// reference content it never had. xet-core's export_as_keyed_shard does
// the same: key each chunk hash with the response's random key and put
// the key in the footer, so a client can only match chunks it already
// holds (it computes the keyed hash locally).
//
// The stored shard's xorb-info is used if it lists the chunk; a shard
// indexed by an older build that does not is still served xorb-only,
// keyed, with this build's expiry and access bookkeeping.
func (s *Server) dedupAnswer(chunk merklehash.Hash) ([]byte, bool, error) {
	s.chunkDedupMu.RLock()
	shardHash, known := s.chunkHashToShard[chunk]
	body := s.shardBodies[shardHash]
	s.chunkDedupMu.RUnlock()
	if !known || body == nil {
		return nil, false, nil
	}
	parsed := map[merklehash.Hash]*shardformat.Shard{}
	home, ok := s.xorbEntryForChunk(shardHash, body, chunk, parsed)
	if !ok {
		shard, parsedOK := parseMemo(shardHash, body, parsed)
		if !parsedOK {
			return nil, false, nil
		}
		answer, err := keyedDedupShard(shard.Xorbs)
		if err != nil {
			return nil, true, err
		}
		s.touchXorbs(shard.Xorbs)
		return answer, true, nil
	}

	xorbs := []shardformat.XorbEntry{home}
	seen := map[merklehash.Hash]bool{home.Header.XorbHash: true}
	total := len(home.Chunks)
	for _, x := range s.xorbsOfFilesReferencing(home.Header.XorbHash) {
		if seen[x] {
			continue
		}
		seen[x] = true
		entry, ok := s.xorbEntry(x, parsed)
		if !ok {
			continue
		}
		if total+len(entry.Chunks) > maxDedupAnswerChunks {
			break
		}
		xorbs = append(xorbs, entry)
		total += len(entry.Chunks)
	}

	answer, err := keyedDedupShard(xorbs)
	if err != nil {
		return nil, true, err
	}
	s.touchXorbs(xorbs)
	return answer, true, nil
}

// keyedDedupShard serializes xorbs as a complete, xorb-only shard whose
// chunk hashes are protected by a fresh random key. The key is generated
// per response - never reused, cached, or derived from content - so one
// answer's key cannot be used to interpret another.
func keyedDedupShard(xorbs []shardformat.XorbEntry) ([]byte, error) {
	var keyBytes [32]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		return nil, fmt.Errorf("generate dedup shard key: %w", err)
	}
	key, err := merklehash.FromRawBytes(keyBytes[:])
	if err != nil {
		return nil, fmt.Errorf("parse dedup shard key: %w", err)
	}
	var buf bytes.Buffer
	if _, err := shardformat.WriteKeyedShardExpiring(&buf, xorbs, key, dedupAnswerExpiry()); err != nil {
		return nil, fmt.Errorf("write keyed dedup shard: %w", err)
	}
	return buf.Bytes(), nil
}

// dedupAnswerExpiry is the ShardKeyExpiry written into every answer:
// now plus dedupAnswerTTL, as Unix seconds. After it the client's shard
// cache no longer loads the answer, so it asks again - which is what
// lets Collect (gc.go) delete a xorb that has not been advertised for
// longer than that.
func dedupAnswerExpiry() uint64 {
	return uint64(time.Now().Add(dedupAnswerTTL).Unix())
}

// touchXorbs records that every xorb in xorbs was just advertised in a
// dedup answer: a client may reference any of them in a shard it uploads
// later without asking again, for as long as the answer is valid, so
// each one's last access moves to now and Collect's grace period
// protects it from that moment.
func (s *Server) touchXorbs(xorbs []shardformat.XorbEntry) {
	now := time.Now()
	s.xorbMu.Lock()
	for _, x := range xorbs {
		s.xorbLastAccess[x.Header.XorbHash] = now
	}
	s.xorbMu.Unlock()
}

// xorbsOfFilesReferencing returns, in term order, the xorb hashes of
// every file whose reconstruction references xorb; files are visited in
// hash order so the answer for a chunk is deterministic. Duplicates are
// left to the caller.
func (s *Server) xorbsOfFilesReferencing(xorb merklehash.Hash) []merklehash.Hash {
	s.fileReconMu.RLock()
	defer s.fileReconMu.RUnlock()
	var files []merklehash.Hash
	for fileHash, entries := range s.fileRecon {
		for _, e := range entries {
			if e.XorbHash == xorb {
				files = append(files, fileHash)
				break
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return bytes.Compare(files[i][:], files[j][:]) < 0 })
	var out []merklehash.Hash
	for _, fileHash := range files {
		for _, e := range s.fileRecon[fileHash] {
			out = append(out, e.XorbHash)
		}
	}
	return out
}

// xorbEntry returns xorb's chunk list from the shard whose xorb-info
// introduced it. parsed memoizes shard parses across one answer.
func (s *Server) xorbEntry(xorb merklehash.Hash, parsed map[merklehash.Hash]*shardformat.Shard) (shardformat.XorbEntry, bool) {
	s.chunkDedupMu.RLock()
	shardHash, known := s.xorbToShard[xorb]
	body := s.shardBodies[shardHash]
	s.chunkDedupMu.RUnlock()
	if !known || body == nil {
		return shardformat.XorbEntry{}, false
	}
	shard, ok := parseMemo(shardHash, body, parsed)
	if !ok {
		return shardformat.XorbEntry{}, false
	}
	for _, x := range shard.Xorbs {
		if x.Header.XorbHash == xorb {
			return x, true
		}
	}
	return shardformat.XorbEntry{}, false
}

// xorbEntryForChunk returns the xorb entry of the stored shard (content
// hash shardHash, body) whose chunk list contains chunk.
func (s *Server) xorbEntryForChunk(shardHash merklehash.Hash, body []byte, chunk merklehash.Hash, parsed map[merklehash.Hash]*shardformat.Shard) (shardformat.XorbEntry, bool) {
	shard, ok := parseMemo(shardHash, body, parsed)
	if !ok {
		return shardformat.XorbEntry{}, false
	}
	for _, x := range shard.Xorbs {
		for _, c := range x.Chunks {
			if c.ChunkHash == chunk {
				return x, true
			}
		}
	}
	return shardformat.XorbEntry{}, false
}

func parseMemo(shardHash merklehash.Hash, body []byte, parsed map[merklehash.Hash]*shardformat.Shard) (*shardformat.Shard, bool) {
	if shard, ok := parsed[shardHash]; ok {
		return shard, shard != nil
	}
	shard, err := shardformat.ReadShard(bytes.NewReader(body))
	if err != nil {
		parsed[shardHash] = nil
		return nil, false
	}
	parsed[shardHash] = shard
	return shard, true
}
