package hubserver

// Tests for the exported ingestion methods (IngestRepoInfo, IngestFile)
// and their read-accessor counterparts (HasRepo, HasRevision, HasFile) -
// the API surface a caller embedding this Server as a caching layer
// (internal/proxyhub) uses instead of rebuilding a repoState/
// revisionState model independently. Driven directly against the
// exported methods and Server's own read methods, not through HTTP -
// hubserver_test.go's existing handler-level tests already cover the
// HTTP boundary these methods sit behind.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guilt/xet-server/internal/merklehash"
)

func newIngestTestServer(t *testing.T) *Server {
	t.Helper()
	return New("http://localhost:9999", newFakeCAS())
}

func TestIngestRepoInfo_CreatesRepoAndRevision(t *testing.T) {
	s := newIngestTestServer(t)
	if s.HasRepo("model", "alice/my-model") {
		t.Fatal("HasRepo() = true before any ingest")
	}

	s.IngestRepoInfo("model", "alice/my-model", "experiment-1")

	if !s.HasRepo("model", "alice/my-model") {
		t.Error("HasRepo() = false after IngestRepoInfo")
	}
	if !s.HasRevision("model", "alice/my-model", "experiment-1") {
		t.Error("HasRevision() = false for the ingested revision")
	}
	// The implicit default revision ("main") must still exist too - the
	// same guarantee getOrCreateRepo already provides for a real commit.
	if !s.HasRevision("model", "alice/my-model", "main") {
		t.Error("HasRevision() = false for the implicit default revision")
	}
}

func TestIngestFile_RecordsFileMetadata(t *testing.T) {
	s := newIngestTestServer(t)
	xetHash := hashFromByte(0xAB)

	if s.HasFile("model", "alice/my-model", "main", "model.bin") {
		t.Fatal("HasFile() = true before any ingest")
	}

	s.IngestFile("model", "alice/my-model", "main", "model.bin", "deadbeef", 1024, xetHash)

	if !s.HasFile("model", "alice/my-model", "main", "model.bin") {
		t.Fatal("HasFile() = false after IngestFile")
	}
}

func TestIngestFile_WithZeroXetHashStillRecordsFile(t *testing.T) {
	// A caller that only knows a file exists (e.g. from a tree listing
	// entry with no xetHash field yet) must still be able to record it -
	// mirrors a freshly-committed file before resolve.go's lazy CAS
	// backfill runs.
	s := newIngestTestServer(t)
	s.IngestFile("model", "alice/my-model", "main", "model.bin", "deadbeef", 1024, merklehash.Hash{})

	if !s.HasFile("model", "alice/my-model", "main", "model.bin") {
		t.Fatal("HasFile() = false after IngestFile with a zero XetHash")
	}
}

func TestIngestFile_ZeroHashDoesNotClobberRicherMetadata(t *testing.T) {
	s := newIngestTestServer(t)
	xetHash := hashFromByte(0xCD)
	s.IngestFile("model", "alice/my-model", "main", "model.bin", "deadbeef", 1024, xetHash)

	// A concurrent repo-info/tree response only knows the sibling path, not
	// its Xet hash or size. It must enrich, never erase, the resolve data.
	s.IngestFile("model", "alice/my-model", "main", "model.bin", "", 0, merklehash.Hash{})

	vs := s.getOrCreateRepo("model", "alice/my-model").getOrCreateRevision("main")
	vs.mu.RLock()
	ref := vs.files["model.bin"]
	vs.mu.RUnlock()
	if ref == nil {
		t.Fatal("file entry vanished after a zero-metadata ingest")
	}
	if ref.XetHash != xetHash {
		t.Errorf("XetHash = %v, want the richer existing %v", ref.XetHash, xetHash)
	}
	if ref.Size != 1024 {
		t.Errorf("Size = %d, want the richer existing 1024", ref.Size)
	}
	if ref.SHA256Hex != "deadbeef" {
		t.Errorf("SHA256Hex = %q, want the richer existing %q", ref.SHA256Hex, "deadbeef")
	}

	// The reverse order must still let a later resolve enrich a bare entry.
	s.IngestFile("model", "alice/my-model", "main", "later.bin", "", 0, merklehash.Hash{})
	laterHash := hashFromByte(0xEF)
	s.IngestFile("model", "alice/my-model", "main", "later.bin", "cafebabe", 2048, laterHash)
	vs.mu.RLock()
	later := vs.files["later.bin"]
	vs.mu.RUnlock()
	if later == nil || later.XetHash != laterHash || later.Size != 2048 || later.SHA256Hex != "cafebabe" {
		t.Errorf("later resolve did not enrich bare entry: %+v", later)
	}
}

func TestHasResolvableFile_RequiresNonZeroXetHash(t *testing.T) {
	s := newIngestTestServer(t)
	xetHash := hashFromByte(0xAB)
	s.IngestFile("model", "alice/my-model", "main", "real.bin", "deadbeef", 1024, xetHash)
	s.IngestFile("model", "alice/my-model", "main", "plain.txt", "cafebabe", 10, merklehash.Hash{})

	if !s.HasResolvableFile("model", "alice/my-model", "main", "real.bin") {
		t.Error("HasResolvableFile() = false for a file with a non-zero Xet hash")
	}
	if s.HasResolvableFile("model", "alice/my-model", "main", "plain.txt") {
		t.Error("HasResolvableFile() = true for a non-Xet file with a zero Xet hash")
	}
	if s.HasResolvableFile("model", "alice/my-model", "main", "missing.bin") {
		t.Error("HasResolvableFile() = true for a missing file")
	}
}

func TestFileSizesByXetHash_ReturnsCommittedFiles(t *testing.T) {
	s := newIngestTestServer(t)
	xetHash := hashFromByte(0xAB)
	s.IngestFile("model", "alice/my-model", "main", "model.bin", "deadbeef", 1024, xetHash)
	// A bare sibling entry must not overwrite the richer one.
	s.IngestFile("model", "alice/my-model", "main", "model.bin", "", 0, merklehash.Hash{})

	sizes := s.FileSizesByXetHash()
	if got := sizes[xetHash]; got != 1024 {
		t.Errorf("FileSizesByXetHash()[%v] = %d, want 1024", xetHash, got)
	}
	if len(sizes) != 1 {
		t.Errorf("FileSizesByXetHash() = %d entries, want 1", len(sizes))
	}
}

func TestFileSizesByXetHash_OmitsZeroHashesAndSizes(t *testing.T) {
	s := newIngestTestServer(t)
	s.IngestFile("model", "alice/my-model", "main", "bare.bin", "deadbeef", 1024, merklehash.Hash{})
	s.IngestFile("model", "alice/my-model", "main", "zero-size.bin", "cafebabe", 0, hashFromByte(0xCD))

	if sizes := s.FileSizesByXetHash(); len(sizes) != 0 {
		t.Errorf("FileSizesByXetHash() = %v, want empty for zero-hash/zero-size refs", sizes)
	}
}

func TestHasRepo_UnknownRepoReturnsFalse(t *testing.T) {
	s := newIngestTestServer(t)
	if s.HasRepo("model", "nobody/nothing") {
		t.Error("HasRepo() = true for a repo never touched")
	}
}

func TestHasRevision_UnknownRevisionReturnsFalse(t *testing.T) {
	s := newIngestTestServer(t)
	s.IngestRepoInfo("model", "alice/my-model", "main")
	if s.HasRevision("model", "alice/my-model", "never-created") {
		t.Error("HasRevision() = true for a revision never created")
	}
}

func TestHasFile_UnknownFileReturnsFalse(t *testing.T) {
	s := newIngestTestServer(t)
	s.IngestRepoInfo("model", "alice/my-model", "main")
	if s.HasFile("model", "alice/my-model", "main", "never-committed.bin") {
		t.Error("HasFile() = true for a file never committed/ingested")
	}
}

func TestIngestCommit_RecordsRealUpstreamOID(t *testing.T) {
	xetHash := hashFromByte(0x11)
	cas := newFakeCAS()
	cas.sizes[xetHash] = 10

	s := New("http://localhost:9999", cas)
	s.IngestCommit("model", "alice/my-model", "main", "realupstreamcommitoid1234567890")
	s.IngestFile("model", "alice/my-model", "main", "model.bin", "deadbeef", 10, xetHash)

	ts := httptest.NewServer(s)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodHead, ts.URL+"/alice/my-model/resolve/main/model.bin", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HEAD error = %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Repo-Commit"); got != "realupstreamcommitoid1234567890" {
		t.Errorf("X-Repo-Commit = %q, want the real upstream commit OID", got)
	}
}

func hashFromByte(b byte) merklehash.Hash {
	var buf [32]byte
	for i := range buf {
		buf[i] = b
	}
	h, _ := merklehash.FromRawBytes(buf[:])
	return h
}
