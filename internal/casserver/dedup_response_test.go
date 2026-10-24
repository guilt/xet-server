package casserver

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/shardformat"
)

// uploadFooterlessShard sends a shard the way a real client does
// (read_shard_to_bytes_remove_footer in xet-core): header with
// FooterSize 0, file-info section with bookend, xorb-info section with
// bookend, and nothing after - no lookup tables, no footer.
func uploadFooterlessShard(t *testing.T, ts *httptest.Server, fileHash, xorbHash merklehash.Hash, chunkHashes []merklehash.Hash, sizes []uint32) {
	t.Helper()
	var total uint32
	for _, n := range sizes {
		total += n
	}
	var up bytes.Buffer
	shardformat.WriteHeader(&up, shardformat.Header{Version: 2, FooterSize: 0})
	shardformat.WriteFileDataSequenceHeader(&up, shardformat.FileDataSequenceHeader{FileHash: fileHash, NumEntries: 1})
	shardformat.WriteFileDataSequenceEntry(&up, shardformat.FileDataSequenceEntry{XorbHash: xorbHash, UnpackedSegmentBytes: total, ChunkIndexStart: 0, ChunkIndexEnd: uint32(len(chunkHashes))})
	shardformat.WriteFileDataSequenceHeader(&up, shardformat.BookendFileHeader())
	shardformat.WriteXorbChunkSequenceHeader(&up, shardformat.XorbChunkSequenceHeader{XorbHash: xorbHash, NumEntries: uint32(len(chunkHashes)), NumBytesInXorb: total})
	var off uint32
	for i, h := range chunkHashes {
		shardformat.WriteXorbChunkSequenceEntry(&up, shardformat.XorbChunkSequenceEntry{ChunkHash: h, ChunkByteRangeStart: off, UnpackedSegmentBytes: sizes[i]})
		off += sizes[i]
	}
	shardformat.WriteXorbChunkSequenceHeader(&up, shardformat.BookendXorbHeader())

	resp, err := http.Post(ts.URL+"/v1/shards", "application/octet-stream", bytes.NewReader(up.Bytes()))
	if err != nil {
		t.Fatalf("upload shard: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload shard: status %d", resp.StatusCode)
	}
}

// fetchDedupShard performs the global-dedup query for chunk and parses
// the response the way a real client does: as a complete shard file
// (MDBShardInfo::load_from_reader), which seeks to a footer at EOF and
// requires footer version 1.
func fetchDedupShard(t *testing.T, ts *httptest.Server, chunk merklehash.Hash) *shardformat.Shard {
	t.Helper()
	resp, err := http.Get(ts.URL + "/v1/chunks/" + chunkDedupPrefix + "/" + chunk.Hex())
	if err != nil {
		t.Fatalf("dedup query: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dedup query: status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	shard, err := shardformat.ReadShard(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("dedup response does not parse: %v", err)
	}
	return shard
}

// A client uploads its shard with the footer and lookup tables stripped,
// but loads whatever GET /v1/chunks/{prefix}/{hash} returns with a reader
// that requires a version-1 footer at EOF. The response must therefore be
// a complete shard file, whatever shape the upload had. Seen in practice:
// git-xet 0.2.1 on a second machine (no local shard cache to dedup from)
// failed every push that hit a dedup match with "MerkleDB Shard error:
// Shard version error: Expected footer version 1, got 0". A single
// machine never sees it, because the uploader dedups against its own
// cached copy and never fetches the shard back.
func TestChunkDedup_ResponseIsACompleteShardFile(t *testing.T) {
	ts, srv := newTestServer(t)
	blob, xorbHash, chunkHashes := buildXorb(t, [][]byte{[]byte("uploaded without"), []byte("a footer")})
	resp, err := http.Post(ts.URL+"/v1/xorbs/default/"+xorbHash.Hex(), "application/octet-stream", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	fileHash := merklehash.ComputeDataHash([]byte("uploaded withouta footer"))
	uploadFooterlessShard(t, ts, fileHash, xorbHash, chunkHashes, []uint32{16, 8})

	shard := fetchDedupShard(t, ts, chunkHashes[1])
	if shard.Header.FooterSize == 0 {
		t.Fatalf("dedup response has FooterSize 0: it is the raw upload, which a client cannot load")
	}
	if shard.Footer.Version != 1 {
		t.Fatalf("dedup response footer version = %d, want 1", shard.Footer.Version)
	}
	// Xorb-info only, like xet-core's reference client answers: the
	// querying client uses the chunk lookup, never the file entries.
	if shard.Footer.ChunkLookupNumEntry != 2 || len(shard.Xorbs) != 1 || len(shard.Files) != 0 {
		t.Fatalf("dedup response: chunkLookup=%d xorbs=%d files=%d, want 2/1/0", shard.Footer.ChunkLookupNumEntry, len(shard.Xorbs), len(shard.Files))
	}
	if shard.Footer.ChunkHashHMACKey.IsZero() {
		t.Fatalf("dedup response has a zero chunk-hash HMAC key: raw chunk hashes leak to every caller")
	}

	// The same holds for a server restored from a snapshot, including
	// one written by a build that stored the raw upload.
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := srv.Snapshot(path); err != nil {
		t.Fatal(err)
	}
	ts2, restored := newTestServer(t)
	if err := restored.LoadSnapshot(path); err != nil {
		t.Fatal(err)
	}
	if again := fetchDedupShard(t, ts2, chunkHashes[0]); again.Header.FooterSize == 0 || again.Footer.Version != 1 {
		t.Fatalf("after snapshot restore: FooterSize=%d footer v%d", again.Header.FooterSize, again.Footer.Version)
	}
}
