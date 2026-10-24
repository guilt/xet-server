package casserver

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/shardformat"
)

// uploadFooterlessShardOf sends a shard the way a real client does (no
// footer, no lookup tables) with arbitrary file and xorb sections. A
// real upload's xorb-info lists only the xorbs that upload created, so
// xorbs need not cover every xorb the files reference.
func uploadFooterlessShardOf(t *testing.T, ts *httptest.Server, files []shardformat.FileEntry, xorbs []shardformat.XorbEntry) {
	t.Helper()
	var up bytes.Buffer
	shardformat.WriteHeader(&up, shardformat.Header{Version: 2, FooterSize: 0})
	for _, f := range files {
		h := f.Header
		h.NumEntries = uint32(len(f.Entries))
		shardformat.WriteFileDataSequenceHeader(&up, h)
		for _, e := range f.Entries {
			shardformat.WriteFileDataSequenceEntry(&up, e)
		}
	}
	shardformat.WriteFileDataSequenceHeader(&up, shardformat.BookendFileHeader())
	for _, x := range xorbs {
		h := x.Header
		h.NumEntries = uint32(len(x.Chunks))
		shardformat.WriteXorbChunkSequenceHeader(&up, h)
		for _, c := range x.Chunks {
			shardformat.WriteXorbChunkSequenceEntry(&up, c)
		}
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

// xorbEntryOf describes payloads as one xorb's chunk list.
func xorbEntryOf(xorbHash merklehash.Hash, chunkHashes []merklehash.Hash, payloads [][]byte) shardformat.XorbEntry {
	var x shardformat.XorbEntry
	x.Header.XorbHash = xorbHash
	var off uint32
	for i, h := range chunkHashes {
		n := uint32(len(payloads[i]))
		x.Chunks = append(x.Chunks, shardformat.XorbChunkSequenceEntry{ChunkHash: h, ChunkByteRangeStart: off, UnpackedSegmentBytes: n})
		off += n
	}
	x.Header.NumBytesInXorb = off
	return x
}

func xorbHashes(shard *shardformat.Shard) []string {
	var out []string
	for _, x := range shard.Xorbs {
		out = append(out, x.Header.XorbHash.Hex()[:8])
	}
	return out
}

// A file is uploaded, then re-uploaded with its first chunk edited. The
// edit's shard lists only the one new xorb, because the uploader deduped
// the rest against its own cache. A second machine editing the file
// again queries the first chunk (xet-core always does, then at most once
// per 256 chunks) and must get an answer that lets it skip the whole
// file, not just the edited chunk: the answer covers every xorb of every
// file that references the chunk's xorb.
func TestChunkDedup_AnswerCoversTheFile(t *testing.T) {
	ts, srv := newTestServer(t)

	// v1: xorb A holds the whole file.
	payloadsA := [][]byte{[]byte("first chunk of the file"), []byte("second chunk"), []byte("third chunk, unchanged")}
	blobA, xorbA, chunksA := buildXorb(t, payloadsA)
	resp, err := http.Post(ts.URL+"/v1/xorbs/"+xorbPrefix+"/"+xorbA.Hex(), "application/octet-stream", bytes.NewReader(blobA))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	entryA := xorbEntryOf(xorbA, chunksA, payloadsA)
	fileV1 := shardformat.FileEntry{
		Header:  shardformat.FileDataSequenceHeader{FileHash: merklehash.ComputeDataHash(bytes.Join(payloadsA, nil))},
		Entries: []shardformat.FileDataSequenceEntry{{XorbHash: xorbA, UnpackedSegmentBytes: entryA.Header.NumBytesInXorb, ChunkIndexStart: 0, ChunkIndexEnd: 3}},
	}
	uploadFooterlessShardOf(t, ts, []shardformat.FileEntry{fileV1}, []shardformat.XorbEntry{entryA})

	// v2: the first chunk edited; only xorb B is new, and the upload's
	// xorb-info lists only B.
	payloadsB := [][]byte{[]byte("FIRST chunk, edited")}
	blobB, xorbB, chunksB := buildXorb(t, payloadsB)
	resp, err = http.Post(ts.URL+"/v1/xorbs/"+xorbPrefix+"/"+xorbB.Hex(), "application/octet-stream", bytes.NewReader(blobB))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	entryB := xorbEntryOf(xorbB, chunksB, payloadsB)
	fileV2 := shardformat.FileEntry{
		Header: shardformat.FileDataSequenceHeader{FileHash: merklehash.ComputeDataHash(bytes.Join([][]byte{payloadsB[0], payloadsA[1], payloadsA[2]}, nil))},
		Entries: []shardformat.FileDataSequenceEntry{
			{XorbHash: xorbB, UnpackedSegmentBytes: entryB.Header.NumBytesInXorb, ChunkIndexStart: 0, ChunkIndexEnd: 1},
			{XorbHash: xorbA, UnpackedSegmentBytes: uint32(len(payloadsA[1]) + len(payloadsA[2])), ChunkIndexStart: 1, ChunkIndexEnd: 3},
		},
	}
	uploadFooterlessShardOf(t, ts, []shardformat.FileEntry{fileV2}, []shardformat.XorbEntry{entryB})

	check := func(t *testing.T, ts *httptest.Server, chunk merklehash.Hash, wantXorbs []merklehash.Hash) {
		t.Helper()
		shard := fetchDedupShard(t, ts, chunk)
		if shard.Footer.Version != 1 || shard.Footer.ChunkHashHMACKey.IsZero() {
			t.Fatalf("answer: footer v%d hmacZero=%v, want v1 with a non-zero key", shard.Footer.Version, shard.Footer.ChunkHashHMACKey.IsZero())
		}
		if len(shard.Xorbs) != len(wantXorbs) {
			t.Fatalf("answer lists xorbs %v, want %d xorbs: the file's other xorbs are on the server and the client will not ask again", xorbHashes(shard), len(wantXorbs))
		}
		for i, want := range wantXorbs {
			if shard.Xorbs[i].Header.XorbHash != want {
				t.Fatalf("answer xorb %d = %s, want %s (order: chunk's own xorb first, then the files' xorbs in term order)", i, shard.Xorbs[i].Header.XorbHash.Hex()[:8], want.Hex()[:8])
			}
		}
		if shard.Footer.ChunkLookupNumEntry != 4 {
			t.Fatalf("answer chunk lookup has %d entries, want 4 (every chunk of both xorbs)", shard.Footer.ChunkLookupNumEntry)
		}
		if len(shard.Files) != 0 {
			t.Fatalf("answer carries %d file entries; want an xorb-only shard", len(shard.Files))
		}
	}

	// The second machine's first query: the edited first chunk. Before
	// this change the answer was v2's upload shard, xorb B alone.
	check(t, ts, chunksB[0], []merklehash.Hash{xorbB, xorbA})
	// A chunk of the original xorb: files referencing A are v1 (A) and
	// v2 (B, A), so the answer covers B as well.
	check(t, ts, chunksA[2], []merklehash.Hash{xorbA, xorbB})

	// The xorb-to-shard index is derived, so a snapshot written by any
	// build (this one included, which does not store it) restores it.
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := srv.Snapshot(path); err != nil {
		t.Fatal(err)
	}
	ts2, restored := newTestServer(t)
	if err := restored.LoadSnapshot(path); err != nil {
		t.Fatal(err)
	}
	check(t, ts2, chunksB[0], []merklehash.Hash{xorbB, xorbA})
}

// An answer never exceeds maxDedupAnswerChunks chunk entries; the xorb
// the chunk lives in comes first and always fits, and further xorbs are
// added whole or not at all.
func TestChunkDedup_AnswerIsBounded(t *testing.T) {
	ts, _ := newTestServer(t)
	small := xorbEntryOf(merklehash.ComputeDataHash([]byte("xorb small")), []merklehash.Hash{merklehash.ComputeDataHash([]byte("the queried chunk"))}, [][]byte{[]byte("the queried chunk")})
	var huge shardformat.XorbEntry
	huge.Header.XorbHash = merklehash.ComputeDataHash([]byte("xorb huge"))
	for i := 0; i < maxDedupAnswerChunks; i++ {
		huge.Chunks = append(huge.Chunks, shardformat.XorbChunkSequenceEntry{ChunkHash: merklehash.ComputeDataHash([]byte(fmt.Sprintf("chunk %d", i))), ChunkByteRangeStart: uint32(i), UnpackedSegmentBytes: 1})
	}
	huge.Header.NumBytesInXorb = uint32(len(huge.Chunks))
	file := shardformat.FileEntry{
		Header: shardformat.FileDataSequenceHeader{FileHash: merklehash.ComputeDataHash([]byte("a file spanning both"))},
		Entries: []shardformat.FileDataSequenceEntry{
			{XorbHash: small.Header.XorbHash, UnpackedSegmentBytes: small.Header.NumBytesInXorb, ChunkIndexStart: 0, ChunkIndexEnd: 1},
			{XorbHash: huge.Header.XorbHash, UnpackedSegmentBytes: huge.Header.NumBytesInXorb, ChunkIndexStart: 0, ChunkIndexEnd: uint32(len(huge.Chunks))},
		},
	}
	uploadFooterlessShardOf(t, ts, []shardformat.FileEntry{file}, []shardformat.XorbEntry{small, huge})

	shard := fetchDedupShard(t, ts, small.Chunks[0].ChunkHash)
	if len(shard.Xorbs) != 1 || shard.Xorbs[0].Header.XorbHash != small.Header.XorbHash {
		t.Fatalf("answer lists xorbs %v; the huge xorb would exceed the bound and must be left out whole", xorbHashes(shard))
	}
	// Queried from inside the huge xorb, that xorb is the home xorb and
	// is served in full; the small one no longer fits.
	shard = fetchDedupShard(t, ts, huge.Chunks[7].ChunkHash)
	if len(shard.Xorbs) != 1 || shard.Footer.ChunkLookupNumEntry != uint64(maxDedupAnswerChunks) {
		t.Fatalf("answer for a chunk of the huge xorb: xorbs %v, lookup %d", xorbHashes(shard), shard.Footer.ChunkLookupNumEntry)
	}
}
