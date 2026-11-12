package casserver

import (
	"bytes"
	"context"
	"testing"

	"github.com/guilt/xet-server/internal/shardformat"
	"github.com/guilt/xet-server/internal/storage/fsstore"
)

func TestReconcileXorbLengths_CorrectsStaleLengthAndFooter(t *testing.T) {
	root := t.TempDir()
	store, err := fsstore.New(root)
	if err != nil {
		t.Fatalf("fsstore.New() error = %v", err)
	}
	srv := New(store)

	blob, hash, _ := buildXorb(t, [][]byte{[]byte("reconcile me")})
	if _, err := srv.IngestXorb(context.Background(), hash, bytes.NewReader(blob)); err != nil {
		t.Fatalf("IngestXorb() error = %v", err)
	}

	// Simulate a stale snapshot: the stored blob is correct, but the index
	// claims a different length (an older/partial snapshot migration).
	srv.xorbMu.Lock()
	srv.xorbRawLength[hash] = int64(len(blob)) + 123
	srv.xorbMu.Unlock()

	srv.ReconcileXorbLengths(context.Background())

	srv.xorbMu.RLock()
	gotLen := srv.xorbRawLength[hash]
	_, footerStillIndexed := srv.xorbFooters[hash]
	srv.xorbMu.RUnlock()
	if gotLen != int64(len(blob)) {
		t.Errorf("xorbRawLength = %d, want actual blob length %d", gotLen, len(blob))
	}
	if footerStillIndexed {
		t.Error("footer was not invalidated after a length correction; it may still describe the stale blob")
	}

	// xorbMeta must re-derive the footer from the actual bytes and report the
	// actual length.
	_, size, ok := srv.xorbMeta(context.Background(), hash)
	if !ok {
		t.Fatal("xorbMeta() reported unknown after reconciliation")
	}
	if size != int64(len(blob)) {
		t.Errorf("xorbMeta() size = %d, want %d", size, len(blob))
	}
}

func TestReconcileXorbLengths_DropsMissingBlobAndInvalidatesFileRecon(t *testing.T) {
	root := t.TempDir()
	store, err := fsstore.New(root)
	if err != nil {
		t.Fatalf("fsstore.New() error = %v", err)
	}
	srv := New(store)

	blob, hash, _ := buildXorb(t, [][]byte{[]byte("gone soon")})
	if _, err := srv.IngestXorb(context.Background(), hash, bytes.NewReader(blob)); err != nil {
		t.Fatalf("IngestXorb() error = %v", err)
	}
	fileHash := hash // any distinct key is enough for this index
	srv.IngestFileRecon(fileHash, []shardformat.FileDataSequenceEntry{{
		XorbHash: hash, UnpackedSegmentBytes: 9, ChunkIndexStart: 0, ChunkIndexEnd: 1,
	}})

	if err := store.Delete(context.Background(), hash.Hex()); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	srv.ReconcileXorbLengths(context.Background())

	srv.xorbMu.RLock()
	_, lengthKnown := srv.xorbRawLength[hash]
	_, footerKnown := srv.xorbFooters[hash]
	srv.xorbMu.RUnlock()
	if lengthKnown || footerKnown {
		t.Errorf("missing blob left metadata behind: lengthKnown=%v footerKnown=%v", lengthKnown, footerKnown)
	}
	if srv.HasFileRecon(fileHash) {
		t.Error("file reconstruction referencing a missing xorb was not invalidated")
	}
}
