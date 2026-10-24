package casserver

// folder_test.go: the synced-folder contract (folder.go). Two servers
// on two directories stand in for two replicas; copying files between
// the directories stands in for the sync tool.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/shardformat"
	"github.com/guilt/xet-server/internal/storage/fsstore"
)

// newFolderServer is a Server whose data dir is dir, laid out as xetd
// lays it out: xorbs under dir/xorbs, shards under dir/shards.
func newFolderServer(t *testing.T, dir string) *Server {
	t.Helper()
	store, err := fsstore.New(filepath.Join(dir, "xorbs"))
	if err != nil {
		t.Fatalf("fsstore.New() error = %v", err)
	}
	srv := New(store)
	if err := srv.SetShardDir(filepath.Join(dir, "shards")); err != nil {
		t.Fatalf("SetShardDir() error = %v", err)
	}
	return srv
}

// pushTestFile does what a git-xet push does to a replica: uploads one
// xorb holding payloads and one shard describing the file made of them,
// with the SHA-256 metadata extension git-lfs downloads key on.
func pushTestFile(t *testing.T, srv *Server, payloads [][]byte) (sha256Hex string, fileHash merklehash.Hash, content []byte) {
	t.Helper()
	blob, xorbHash, chunkHashes := buildXorb(t, payloads)
	if _, err := srv.IngestXorb(context.Background(), xorbHash, bytes.NewReader(blob)); err != nil {
		t.Fatalf("IngestXorb() error = %v", err)
	}
	for _, p := range payloads {
		content = append(content, p...)
	}
	fileHash = merklehash.ComputeDataHash(content)
	sum := sha256.Sum256(content)
	sha256Hex = hex.EncodeToString(sum[:])
	sha, err := merklehash.FromHex(sha256Hex)
	if err != nil {
		t.Fatal(err)
	}

	var chunks []shardformat.XorbChunkSequenceEntry
	var off uint32
	for i, p := range payloads {
		chunks = append(chunks, shardformat.XorbChunkSequenceEntry{ChunkHash: chunkHashes[i], ChunkByteRangeStart: off, UnpackedSegmentBytes: uint32(len(p))})
		off += uint32(len(p))
	}
	var buf bytes.Buffer
	_, err = shardformat.WriteShard(&buf, []shardformat.FileEntry{{
		Header:      shardformat.FileDataSequenceHeader{FileHash: fileHash, NumEntries: 1},
		Entries:     []shardformat.FileDataSequenceEntry{{XorbHash: xorbHash, UnpackedSegmentBytes: uint32(len(content)), ChunkIndexStart: 0, ChunkIndexEnd: uint32(len(payloads))}},
		MetadataExt: &shardformat.FileMetadataExt{SHA256: sha},
	}}, []shardformat.XorbEntry{{
		Header: shardformat.XorbChunkSequenceHeader{XorbHash: xorbHash, NumEntries: uint32(len(payloads)), NumBytesInXorb: off},
		Chunks: chunks,
	}})
	if err != nil {
		t.Fatalf("WriteShard() error = %v", err)
	}
	if err := srv.IngestShard(buf.Bytes()); err != nil {
		t.Fatalf("IngestShard() error = %v", err)
	}
	return sha256Hex, fileHash, content
}

// syncDir copies every regular file under src/sub to dst/sub that dst
// lacks - what an additive sync tool does. Names matching skip are left
// out, to stage a partial sync.
func syncDir(t *testing.T, src, dst, sub string, skip func(name string) bool) {
	t.Helper()
	root := filepath.Join(src, sub)
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if skip != nil && skip(info.Name()) {
			return nil
		}
		target := filepath.Join(dst, sub, rel)
		if _, err := os.Stat(target); err == nil {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sync %s: %v", sub, err)
	}
}

func reconstruct(t *testing.T, srv *Server, fileHash merklehash.Hash, size int) ([]byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := srv.ReconstructFile(context.Background(), fileHash, 0, int64(size)-1, &out)
	return out.Bytes(), err
}

func TestFolder_ShardIsPersistedAndReindexedOnRestart(t *testing.T) {
	dir := t.TempDir()
	a := newFolderServer(t, dir)
	oid, fileHash, content := pushTestFile(t, a, [][]byte{[]byte("first chunk of the file"), []byte("second chunk")})

	shardFiles, _ := os.ReadDir(filepath.Join(dir, "shards"))
	if len(shardFiles) != 1 {
		t.Fatalf("shard dir has %d files, want 1", len(shardFiles))
	}
	body, _ := os.ReadFile(filepath.Join(dir, "shards", shardFiles[0].Name()))
	if merklehash.ComputeDataHash(body).Hex() != shardFiles[0].Name() {
		t.Fatalf("shard file %s is not named by its content hash", shardFiles[0].Name())
	}

	// A fresh process on the same dir, with no snapshot: everything is
	// derived from the files. Xorb footers come from the xorb bytes.
	b := newFolderServer(t, dir)
	if _, err := b.ScanShards(context.Background()); err != nil {
		t.Fatalf("ScanShards() error = %v", err)
	}
	if h, ok := b.XetHashForSHA256(oid); !ok || h != fileHash {
		t.Fatalf("after restart XetHashForSHA256 = %v, %v", h, ok)
	}
	got, err := reconstruct(t, b, fileHash, len(content))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("after restart reconstruct: err %v, %d bytes (want %d)", err, len(got), len(content))
	}
}

func TestFolder_OtherReplicaUploadBecomesVisibleOnMiss(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	a := newFolderServer(t, dirA)
	b := newFolderServer(t, dirB)
	oid, fileHash, content := pushTestFile(t, a, [][]byte{[]byte("pushed on machine A"), []byte("in two chunks")})

	if _, ok := b.XetHashForSHA256(oid); ok {
		t.Fatal("B knows a file before any sync")
	}
	syncDir(t, dirA, dirB, "shards", nil)
	syncDir(t, dirA, dirB, "xorbs", nil)

	// No restart, no timer: the lookup miss itself triggers the rescan
	// (the earlier miss's scan does not throttle it, because the sync
	// moved the directory's mtime).
	if h, ok := b.XetHashForSHA256(oid); !ok || h != fileHash {
		t.Fatalf("after sync XetHashForSHA256 on B = %v, %v", h, ok)
	}
	if missing, err := b.MissingXorbs(context.Background(), fileHash); err != nil || len(missing) != 0 {
		t.Fatalf("MissingXorbs on B = %v, %v", missing, err)
	}
	got, err := reconstruct(t, b, fileHash, len(content))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("B reconstruct: err %v, %d bytes", err, len(got))
	}
}

func TestFolder_ShardBeforeXorbsReportsUnavailable(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	a := newFolderServer(t, dirA)
	b := newFolderServer(t, dirB)
	oid, fileHash, content := pushTestFile(t, a, [][]byte{[]byte("the xorb arrives"), []byte("after the shard")})

	// The sync tool delivered the (small) shard first.
	syncDir(t, dirA, dirB, "shards", nil)
	if _, ok := b.XetHashForSHA256(oid); !ok {
		t.Fatal("B should know the file from the shard alone")
	}
	missing, err := b.MissingXorbs(context.Background(), fileHash)
	if err != nil || len(missing) != 1 {
		t.Fatalf("MissingXorbs = %v, %v; want one missing xorb", missing, err)
	}
	if _, err := reconstruct(t, b, fileHash, len(content)); !errors.Is(err, ErrContentUnavailable) {
		t.Fatalf("reconstruct before xorbs synced: err = %v, want ErrContentUnavailable", err)
	}

	// A half-delivered xorb (truncated, under its final name) counts as
	// absent, not as corrupt data to serve.
	syncDir(t, dirA, dirB, "xorbs", nil)
	var xorbPath string
	filepath.Walk(filepath.Join(dirB, "xorbs"), func(p string, info os.FileInfo, _ error) error {
		if info != nil && !info.IsDir() {
			xorbPath = p
		}
		return nil
	})
	full, _ := os.ReadFile(xorbPath)
	os.WriteFile(xorbPath, full[:len(full)/2], 0o644)
	if missing, _ := b.MissingXorbs(context.Background(), fileHash); len(missing) != 1 {
		t.Fatalf("truncated xorb counted as present: missing = %v", missing)
	}

	// Then it lands whole.
	os.WriteFile(xorbPath, full, 0o644)
	if missing, _ := b.MissingXorbs(context.Background(), fileHash); len(missing) != 0 {
		t.Fatalf("after full sync missing = %v", missing)
	}
	got, err := reconstruct(t, b, fileHash, len(content))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("after full sync reconstruct: err %v", err)
	}
}

func TestFolder_ScanSkipsForeignAndPartialFiles(t *testing.T) {
	dir := t.TempDir()
	a := newFolderServer(t, dir)
	pushTestFile(t, a, [][]byte{[]byte("a real shard lives here too")})
	shards := filepath.Join(dir, "shards")
	files, _ := os.ReadDir(shards)
	real, _ := os.ReadFile(filepath.Join(shards, files[0].Name()))

	// A sync tool's temp file, a stray file, and a truncated shard under
	// a hash name that does not match its content.
	os.WriteFile(filepath.Join(shards, ".syncthing.tmp"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(shards, "notes.txt"), []byte("hello"), 0o644)
	bogus := merklehash.ComputeDataHash([]byte("something else")).Hex()
	os.WriteFile(filepath.Join(shards, bogus), real[:len(real)/2], 0o644)

	b := newFolderServer(t, dir)
	added, err := b.ScanShards(context.Background())
	if err != nil || added != 1 {
		t.Fatalf("ScanShards() = %d, %v; want 1 shard indexed and no error", added, err)
	}
	b.chunkDedupMu.RLock()
	n := len(b.shardBodies)
	b.chunkDedupMu.RUnlock()
	if n != 1 {
		t.Fatalf("%d shard bodies indexed, want 1", n)
	}
	// Idempotent.
	if added, _ := b.ScanShards(context.Background()); added != 0 {
		t.Fatalf("second scan added %d", added)
	}
}

func TestFolder_ChunkDedupSeesOtherReplicasShards(t *testing.T) {
	dirA, dirB := t.TempDir(), t.TempDir()
	a := newFolderServer(t, dirA)
	b := newFolderServer(t, dirB)
	pushTestFile(t, a, [][]byte{[]byte("chunk one on A"), []byte("chunk two on A")})
	_, xorbHash, chunkHashes := buildXorb(t, [][]byte{[]byte("chunk one on A"), []byte("chunk two on A")})
	_ = xorbHash

	if _, known, _ := b.dedupAnswer(chunkHashes[0]); known {
		t.Fatal("B knows A's chunk before sync")
	}
	syncDir(t, dirA, dirB, "shards", nil)
	// The dedup handler's miss path rescans; exercise the same helper
	// the handler uses after a forced rescan.
	if !b.rescanOnMiss() {
		t.Fatal("rescanOnMiss found nothing after sync")
	}
	if _, known, _ := b.dedupAnswer(chunkHashes[1]); !known {
		t.Fatal("B does not offer A's chunk for dedup after sync")
	}
}

// A real client uploads a shard with no footer and no lookup tables; what
// it downloads from the global-dedup endpoint must be a complete shard
// file, or it fails with "Expected footer version 1, got 0" (seen with
// git-xet 0.2.1 on a second machine, which had no local cache to dedup
// from - the original single-client suite never exercised this path).
func TestDedupResponseIsACompleteShardFile(t *testing.T) {
	srv := newFolderServer(t, t.TempDir())
	blob, xorbHash, chunkHashes := buildXorb(t, [][]byte{[]byte("uploaded without"), []byte("a footer")})
	if _, err := srv.IngestXorb(context.Background(), xorbHash, bytes.NewReader(blob)); err != nil {
		t.Fatal(err)
	}
	fileHash := merklehash.ComputeDataHash([]byte("uploaded withouta footer"))

	// The client's upload form: header (FooterSize 0), file section with
	// bookend, xorb section with bookend, nothing else.
	var up bytes.Buffer
	shardformat.WriteHeader(&up, shardformat.Header{Version: 2, FooterSize: 0})
	shardformat.WriteFileDataSequenceHeader(&up, shardformat.FileDataSequenceHeader{FileHash: fileHash, NumEntries: 1})
	shardformat.WriteFileDataSequenceEntry(&up, shardformat.FileDataSequenceEntry{XorbHash: xorbHash, UnpackedSegmentBytes: 24, ChunkIndexStart: 0, ChunkIndexEnd: 2})
	shardformat.WriteFileDataSequenceHeader(&up, shardformat.BookendFileHeader())
	shardformat.WriteXorbChunkSequenceHeader(&up, shardformat.XorbChunkSequenceHeader{XorbHash: xorbHash, NumEntries: 2, NumBytesInXorb: 24})
	shardformat.WriteXorbChunkSequenceEntry(&up, shardformat.XorbChunkSequenceEntry{ChunkHash: chunkHashes[0], ChunkByteRangeStart: 0, UnpackedSegmentBytes: 16})
	shardformat.WriteXorbChunkSequenceEntry(&up, shardformat.XorbChunkSequenceEntry{ChunkHash: chunkHashes[1], ChunkByteRangeStart: 16, UnpackedSegmentBytes: 8})
	shardformat.WriteXorbChunkSequenceHeader(&up, shardformat.BookendXorbHeader())
	if err := srv.IngestShard(up.Bytes()); err != nil {
		t.Fatalf("IngestShard() error = %v", err)
	}

	// The file on disk is the raw upload (content-addressed by it)...
	files, _ := os.ReadDir(srv.ShardDir())
	onDisk, _ := os.ReadFile(filepath.Join(srv.ShardDir(), files[0].Name()))
	if !bytes.Equal(onDisk, up.Bytes()) {
		t.Fatal("persisted shard is not the raw upload")
	}
	// ...but the dedup response is a complete shard file.
	served, known, _ := srv.dedupAnswer(chunkHashes[1])
	if !known {
		t.Fatal("chunk not indexed")
	}
	full, err := shardformat.ReadShard(bytes.NewReader(served))
	if err != nil {
		t.Fatalf("served shard does not parse: %v", err)
	}
	if full.Header.FooterSize == 0 || full.Footer.Version != 1 || full.Footer.ChunkLookupNumEntry != 2 || len(full.Xorbs) != 1 || len(full.Files) != 0 {
		t.Fatalf("served shard: footerSize=%d footer v%d chunkLookup=%d xorbs=%d files=%d", full.Header.FooterSize, full.Footer.Version, full.Footer.ChunkLookupNumEntry, len(full.Xorbs), len(full.Files))
	}
	if full.Footer.ChunkHashHMACKey.IsZero() {
		t.Fatal("served shard has a zero chunk-hash key")
	}
	for i, c := range full.Xorbs[0].Chunks {
		if want := chunkHashes[i].HMAC(full.Footer.ChunkHashHMACKey); c.ChunkHash != want {
			t.Fatalf("served chunk %d = %s, want keyed %s", i, c.ChunkHash.Hex()[:8], want.Hex()[:8])
		}
	}
	// A restart that rescans the raw file serves the same complete form,
	// with a fresh key (the response is random per query by design).
	again := newFolderServer(t, filepath.Dir(srv.ShardDir()))
	again.ScanShards(context.Background())
	served2, known, _ := again.dedupAnswer(chunkHashes[0])
	if !known {
		t.Fatal("chunk not indexed after rescan")
	}
	full2, err := shardformat.ReadShard(bytes.NewReader(served2))
	if err != nil {
		t.Fatalf("rescanned served shard does not parse: %v", err)
	}
	if full2.Header.FooterSize == 0 || full2.Footer.Version != 1 || full2.Footer.ChunkHashHMACKey.IsZero() || len(full2.Files) != 0 {
		t.Fatalf("rescanned served shard: footerSize=%d footer v%d keyZero=%v files=%d", full2.Header.FooterSize, full2.Footer.Version, full2.Footer.ChunkHashHMACKey.IsZero(), len(full2.Files))
	}
	if full2.Footer.ChunkHashHMACKey == full.Footer.ChunkHashHMACKey {
		t.Fatal("two dedup responses reused the same key")
	}
}
