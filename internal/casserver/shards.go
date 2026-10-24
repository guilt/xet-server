package casserver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/shardformat"
)

// chunkDedupPrefix is the prefix xet-core's openapi spec documents for
// GET /v1/chunks/{prefix}/{hash} (PrefixGlobalDedupeParam). Real clients
// disagree with the spec: cas_client/src/remote_client.rs in xet-core
// >= 1.5 (git-xet 0.2.1, hf_xet 1.6.0) queries with PREFIX_DEFAULT
// ("default", the same prefix as xorb uploads), so handleChunkDedup
// accepts both - see isChunkDedupPrefix.
const chunkDedupPrefix = "default-merkledb"

// isChunkDedupPrefix reports whether prefix is one a real client uses on
// the global dedup endpoint: the documented one or xorbPrefix.
func isChunkDedupPrefix(prefix string) bool {
	return prefix == chunkDedupPrefix || prefix == xorbPrefix
}

// maxShardBytes caps a single shard upload's body size. Shards describe
// one or more whole files' chunk/xorb manifests, so their size scales with
// the files they cover - a real hf_xet client uploading a single multi-GB
// model sends one shard enumerating every chunk hash of the file, which
// easily exceeds 16 MiB (the previous cap, sized for a single xorb's worth
// of entries) and caused real `hf upload` of large files to fail with 413.
// This cap exists to bound IngestShard's io.ReadAll, which buffers the
// whole body in memory rather than streaming to a temp file - it must stay
// large enough for genuine single-file shards while still bounding a
// hostile client's memory growth.
const maxShardBytes = 512 * 1024 * 1024

// handleUploadShard implements POST /v1/shards: read the body (capped at
// maxShardBytes) and delegate to IngestShard - see its doc comment for
// what indexing a shard actually does.
func (s *Server) handleUploadShard(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxShardBytes)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			httpError(w, "read body (exceeds max shard size or connection error): "+err.Error(), http.StatusRequestEntityTooLarge)
		} else {
			httpError(w, "read body: "+err.Error(), http.StatusBadRequest)
		}
		return
	}

	if err := s.IngestShard(body); err != nil {
		httpError(w, "malformed shard: "+err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, uploadShardResponse{Result: 1})
}

// IngestShard parses body as a serialized shard and merges its
// file-reconstruction entries into this server's in-memory fileRecon
// index (keyed by file hash), and indexes every chunk hash referenced by
// the shard's xorb-info section against body itself, backing the global
// chunk-dedup lookup (GET /v1/chunks/{prefix}/{hash} - see
// handleChunkDedup): the real wire contract for that endpoint is "return
// the shard bytes that reference this chunk," which a real client parses
// itself to discover chunks it can dedup against without re-uploading -
// see docs/PROTOCOL.md's global-dedup section for the full story of how
// this was confirmed against xet-core's own client source.
//
// Exported so a caller embedding this Server as a caching layer (e.g.
// internal/proxyhub or internal/proxycas, relaying a real client's shard
// upload write-through to a real upstream CAS and wanting this server to
// also reflect it immediately) can feed it shard bytes through the
// identical parsing/indexing path handleUploadShard uses.
func (s *Server) IngestShard(body []byte) error {
	// Parse first so a malformed body is rejected before anything is
	// written; then persist before indexing, so a crash between the two
	// leaves a file the next startup's ScanShards re-indexes rather
	// than an index entry with no file behind it.
	if _, err := shardformat.ReadShard(bytes.NewReader(body)); err != nil {
		return err
	}
	s.gcMu.RLock()
	defer s.gcMu.RUnlock()
	shardHash := merklehash.ComputeDataHash(body)
	if err := s.persistShard(shardHash, body); err != nil {
		return fmt.Errorf("persist shard: %w", err)
	}
	return s.indexShard(body, shardHash)
}

// indexShard merges an already-validated shard body (content hash
// shardHash) into the in-memory indices. Shared by IngestShard (an
// upload) and ScanShards (a file another replica wrote to the shard
// dir); idempotent for a body seen before.
func (s *Server) indexShard(body []byte, shardHash merklehash.Hash) error {
	shard, err := shardformat.ReadShard(bytes.NewReader(body))
	if err != nil {
		return err
	}

	s.fileReconMu.Lock()
	for _, f := range shard.Files {
		s.fileRecon[f.Header.FileHash] = f.Entries
		hasExt := f.MetadataExt != nil
		var sha256Hex string
		if f.MetadataExt != nil {
			// FileMetadataExt.SHA256 reuses the 32-byte merklehash.Hash type
			// for storage, but real hf_xet clients write it through the same
			// byte-order transform as a genuine Merkle hash's Hex() (word
			// reversal per 8-byte little-endian group) - confirmed by
			// capturing a real upload and comparing MetadataExt.SHA256's raw
			// bytes against the plain SHA-256 in the commit payload's
			// lfsFile.oid: Hex() of the former equals the latter exactly.
			// A raw-byte hex encode (hex.EncodeToString(Bytes())) silently
			// produces a different string that never matches oid, so the
			// resolve/download path's sha256->Xet-hash lookup always missed.
			sha256Hex = f.MetadataExt.SHA256.Hex()
			s.sha256Mu.Lock()
			s.sha256ToXet[sha256Hex] = f.Header.FileHash
			s.sha256Mu.Unlock()
		}
		slog.Debug("shard file indexed", "fileHash", f.Header.FileHash.Hex(), "hasMetadataExt", hasExt, "sha256Hex", sha256Hex)
	}
	s.fileReconMu.Unlock()

	// Every chunk in this shard maps to THIS shard's own content-address
	// hash, and the raw uploaded shard body is stored once under that
	// same hash - the dedup layout snapshot memory-blowup fix relies on
	// (see chunkHashToShard's doc comment). ComputeDataHash is
	// content-addressed, so an identical shard body (same content,
	// uploaded twice) resolves to the same entry with no duplication of
	// storage. The raw body is what the chunk index is keyed against;
	// dedupAnswer rebuilds a keyed, footer-carrying answer from it on
	// every query (see dedupAnswer), so no keyed body is ever stored.
	var chunkCount int
	s.chunkDedupMu.Lock()
	if _, exists := s.shardBodies[shardHash]; !exists {
		s.shardBodies[shardHash] = body
	}
	if _, exists := s.shardIndexedAt[shardHash]; !exists {
		// Kept across Collect's rebuild, so a collection does not make
		// every surviving shard look freshly pushed.
		s.shardIndexedAt[shardHash] = time.Now()
	}
	for _, x := range shard.Xorbs {
		if _, exists := s.xorbToShard[x.Header.XorbHash]; !exists {
			s.xorbToShard[x.Header.XorbHash] = shardHash
		}
		for _, c := range x.Chunks {
			// First shard to reference a given chunk hash wins; later
			// shards referencing the same (already-deduplicated) chunk
			// don't need to replace it - any shard referencing the chunk
			// is equally valid for a client's dedup purposes.
			if _, exists := s.chunkHashToShard[c.ChunkHash]; !exists {
				s.chunkHashToShard[c.ChunkHash] = shardHash
				chunkCount++
			}
		}
	}
	s.chunkDedupMu.Unlock()
	slog.Debug("shard chunk-dedup index updated", "newChunkEntries", chunkCount, "shardHash", shardHash.Hex())

	return nil
}
