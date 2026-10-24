package casserver

// gc_test.go: the keep-set garbage collector (gc.go). Files are built
// over several xorbs, some shared, the way real uploads leave them: a
// later upload that deduplicated a xorb references it in its file terms
// but does not repeat its xorb-info.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/shardformat"
	"github.com/guilt/xet-server/internal/storage"
	"github.com/guilt/xet-server/internal/storage/fsstore"
)

// filePart is one xorb's worth of a composite file. declare says whether
// the file's shard carries the xorb-info for it (a xorb this upload
// created) or only references it in file terms (a xorb it deduplicated).
type filePart struct {
	payloads [][]byte
	declare  bool
}

// pushComposite uploads every part's xorb and one shard describing the
// file made of the parts, with the SHA-256 extension. Returns the file's
// identities and its xorb hashes in part order.
func pushComposite(t *testing.T, srv *Server, parts []filePart) (sha256Hex string, fileHash merklehash.Hash, content []byte, xorbs []merklehash.Hash) {
	t.Helper()
	var entries []shardformat.FileDataSequenceEntry
	var xorbInfos []shardformat.XorbEntry
	for _, p := range parts {
		blob, xorbHash, chunkHashes := buildXorb(t, p.payloads)
		if _, err := srv.IngestXorb(context.Background(), xorbHash, bytes.NewReader(blob)); err != nil {
			t.Fatalf("IngestXorb() error = %v", err)
		}
		xorbs = append(xorbs, xorbHash)
		var partBytes uint32
		for _, pl := range p.payloads {
			content = append(content, pl...)
			partBytes += uint32(len(pl))
		}
		entries = append(entries, shardformat.FileDataSequenceEntry{XorbHash: xorbHash, UnpackedSegmentBytes: partBytes, ChunkIndexStart: 0, ChunkIndexEnd: uint32(len(p.payloads))})
		if p.declare {
			info := xorbEntryOf(xorbHash, chunkHashes, p.payloads)
			info.Header.NumEntries = uint32(len(info.Chunks))
			xorbInfos = append(xorbInfos, info)
		}
	}
	fileHash = merklehash.ComputeDataHash(content)
	sum := sha256.Sum256(content)
	sha256Hex = hex.EncodeToString(sum[:])
	sha, err := merklehash.FromHex(sha256Hex)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := shardformat.WriteShard(&buf, []shardformat.FileEntry{{
		Header:      shardformat.FileDataSequenceHeader{FileHash: fileHash, NumEntries: uint32(len(entries))},
		Entries:     entries,
		MetadataExt: &shardformat.FileMetadataExt{SHA256: sha},
	}}, xorbInfos); err != nil {
		t.Fatalf("WriteShard() error = %v", err)
	}
	if err := srv.IngestShard(buf.Bytes()); err != nil {
		t.Fatalf("IngestShard() error = %v", err)
	}
	return sha256Hex, fileHash, content, xorbs
}

func payloadsOf(seed byte, n int) [][]byte {
	var out [][]byte
	for i := 0; i < n; i++ {
		out = append(out, bytes.Repeat([]byte{seed, byte(i)}, 700+i))
	}
	return out
}

// gcFixture is two files sharing a xorb, plus an orphan xorb no shard
// names. bob pushed first (declaring XS and X2); alice pushed after and
// deduplicated XS, so her shard declares only X1.
type gcFixture struct {
	dir                  string
	srv                  *Server
	shaA, shaB           string
	fileA, fileB         merklehash.Hash
	contentA, contentB   []byte
	x1, x2, xs, x3       merklehash.Hash
	chunkInXS, chunkInX2 merklehash.Hash
}

func newGCFixture(t *testing.T) *gcFixture {
	t.Helper()
	f := &gcFixture{dir: t.TempDir()}
	f.srv = newFolderServer(t, f.dir)
	shared := payloadsOf('S', 2)
	var xb []merklehash.Hash
	f.shaB, f.fileB, f.contentB, xb = pushComposite(t, f.srv, []filePart{{shared, true}, {payloadsOf('2', 2), true}})
	f.xs, f.x2 = xb[0], xb[1]
	var xa []merklehash.Hash
	f.shaA, f.fileA, f.contentA, xa = pushComposite(t, f.srv, []filePart{{payloadsOf('1', 2), true}, {shared, false}})
	f.x1 = xa[0]
	blob, x3, _ := buildXorb(t, payloadsOf('3', 2))
	if _, err := f.srv.IngestXorb(context.Background(), x3, bytes.NewReader(blob)); err != nil {
		t.Fatal(err)
	}
	f.x3 = x3
	f.chunkInXS = merklehash.ComputeDataHash(shared[1])
	f.chunkInX2 = merklehash.ComputeDataHash(payloadsOf('2', 2)[0])
	return f
}

// backdate makes every xorb and shard look untouched for age: last
// access and index times in memory, and file mtimes on disk.
func (f *gcFixture) backdate(t *testing.T, age time.Duration) {
	t.Helper()
	then := time.Now().Add(-age)
	f.srv.xorbMu.Lock()
	for h := range f.srv.xorbLastAccess {
		f.srv.xorbLastAccess[h] = then
	}
	f.srv.xorbMu.Unlock()
	f.srv.chunkDedupMu.Lock()
	for h := range f.srv.shardIndexedAt {
		f.srv.shardIndexedAt[h] = then
	}
	f.srv.chunkDedupMu.Unlock()
	for _, sub := range []string{"xorbs", "shards"} {
		err := filepath.Walk(filepath.Join(f.dir, sub), func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			return os.Chtimes(path, then, then)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func (f *gcFixture) has(t *testing.T, x merklehash.Hash) bool {
	t.Helper()
	ok, err := f.srv.HasXorbBytes(context.Background(), x)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func shardFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "shards"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestCollect_KeepsWhatTheKeepSetReaches(t *testing.T) {
	f := newGCFixture(t)
	f.backdate(t, 48*time.Hour)
	before := shardFiles(t, f.dir)
	if len(before) != 2 {
		t.Fatalf("shard files before = %v, want 2", before)
	}

	report, err := f.srv.Collect(context.Background(), GCOptions{Keep: []string{strings.ToUpper(f.shaA)}})
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	want := GCReport{KeepOIDs: 1, FilesKept: 1, FilesDropped: 1, ShardsKept: 1, ShardsRewritten: 1, XorbsKept: 2, XorbsDeleted: 2}
	got := report
	got.XorbsKeptBytes, got.XorbsDeletedBytes = 0, 0
	if len(report.Errors) != 0 || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("report = %+v, want %+v", got, want)
	}
	if report.XorbsDeletedBytes == 0 || report.XorbsKeptBytes == 0 {
		t.Errorf("byte counts missing: %+v", report)
	}

	// The store: alice's xorbs and the shared one stay, bob's own and
	// the orphan are gone.
	for _, c := range []struct {
		name string
		x    merklehash.Hash
		want bool
	}{{"X1", f.x1, true}, {"XS", f.xs, true}, {"X2", f.x2, false}, {"X3 orphan", f.x3, false}} {
		if got := f.has(t, c.x); got != c.want {
			t.Errorf("store has %s = %v, want %v", c.name, got, c.want)
		}
	}
	// The index: alice's file is whole, bob's is gone.
	if out, err := reconstruct(t, f.srv, f.fileA, len(f.contentA)); err != nil || !bytes.Equal(out, f.contentA) {
		t.Errorf("file A after gc: err = %v, equal = %v", err, bytes.Equal(out, f.contentA))
	}
	if _, err := reconstruct(t, f.srv, f.fileB, len(f.contentB)); !errors.Is(err, ErrUnknownFile) {
		t.Errorf("file B after gc: err = %v, want ErrUnknownFile", err)
	}
	if _, ok := f.srv.XetHashForSHA256(f.shaB); ok {
		t.Error("bob's sha256 still resolves")
	}
	if _, ok := f.srv.XetHashForSHA256(f.shaA); !ok {
		t.Error("alice's sha256 no longer resolves")
	}
	// Dedup: a chunk of the shared xorb is still answered, and the
	// answer no longer advertises the deleted xorb; a chunk of the
	// deleted xorb is unknown.
	answer, known, _ := f.srv.dedupAnswer(f.chunkInXS)
	if !known {
		t.Fatal("chunk in the shared xorb is no longer known")
	}
	shard, err := shardformat.ReadShard(bytes.NewReader(answer))
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range shard.Xorbs {
		if x.Header.XorbHash == f.x2 {
			t.Error("dedup answer still advertises the deleted xorb")
		}
	}
	if _, known, _ := f.srv.dedupAnswer(f.chunkInX2); known {
		t.Error("chunk of the deleted xorb is still answered")
	}
	// The shard dir: bob's original is gone, its rewrite is there under
	// its own hash, and a cold start over the directory agrees.
	after := shardFiles(t, f.dir)
	if len(after) != 2 {
		t.Fatalf("shard files after = %v, want 2", after)
	}
	for _, name := range after {
		body, _ := os.ReadFile(filepath.Join(f.dir, "shards", name))
		if merklehash.ComputeDataHash(body).Hex() != name {
			t.Errorf("shard file %s does not hash to its name", name)
		}
	}
	snap := filepath.Join(f.dir, "snap.json")
	if err := f.srv.Snapshot(snap); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"snapshot", "scan"} {
		restarted := newFolderServer(t, f.dir)
		if mode == "snapshot" {
			if err := restarted.LoadSnapshot(snap); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := restarted.ScanShards(context.Background()); err != nil {
			t.Fatal(err)
		}
		if out, err := reconstruct(t, restarted, f.fileA, len(f.contentA)); err != nil || !bytes.Equal(out, f.contentA) {
			t.Errorf("%s restart: file A err = %v", mode, err)
		}
		if _, err := reconstruct(t, restarted, f.fileB, len(f.contentB)); !errors.Is(err, ErrUnknownFile) {
			t.Errorf("%s restart: file B err = %v, want ErrUnknownFile", mode, err)
		}
		if _, known, _ := restarted.dedupAnswer(f.chunkInX2); known {
			t.Errorf("%s restart: chunk of the deleted xorb is answered again", mode)
		}
	}
}

func TestCollect_DryRunChangesNothing(t *testing.T) {
	f := newGCFixture(t)
	f.backdate(t, 48*time.Hour)
	report, err := f.srv.Collect(context.Background(), GCOptions{Keep: []string{f.shaA}, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !report.DryRun || report.XorbsDeleted != 2 || report.ShardsRewritten != 1 || report.FilesDropped != 1 {
		t.Errorf("dry-run report = %+v", report)
	}
	for _, x := range []merklehash.Hash{f.x1, f.x2, f.xs, f.x3} {
		if !f.has(t, x) {
			t.Errorf("dry run deleted %s", x.Hex()[:8])
		}
	}
	if out, err := reconstruct(t, f.srv, f.fileB, len(f.contentB)); err != nil || !bytes.Equal(out, f.contentB) {
		t.Errorf("dry run dropped file B: err = %v", err)
	}
	if got := shardFiles(t, f.dir); len(got) != 2 {
		t.Errorf("dry run touched the shard dir: %v", got)
	}
}

func TestCollect_GraceProtectsRecentlyAdvertisedXorbs(t *testing.T) {
	f := newGCFixture(t)
	f.backdate(t, 48*time.Hour)
	// A dedup answer for a chunk of the shared xorb advertises XS and
	// every xorb of both files; the orphan is never advertised.
	if _, known, _ := f.srv.dedupAnswer(f.chunkInXS); !known {
		t.Fatal("fixture: shared chunk unknown")
	}
	report, err := f.srv.Collect(context.Background(), GCOptions{Grace: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesDropped != 2 || report.ShardsDeleted != 2 {
		t.Errorf("report = %+v, want both files and shards dropped", report)
	}
	if report.XorbsDeleted != 1 || report.XorbsDeferred != 3 {
		t.Errorf("deleted %d, deferred %d; want the orphan deleted and the three advertised ones deferred", report.XorbsDeleted, report.XorbsDeferred)
	}
	if f.has(t, f.x3) {
		t.Error("orphan survived")
	}
	for _, x := range []merklehash.Hash{f.x1, f.x2, f.xs} {
		if !f.has(t, x) {
			t.Errorf("advertised xorb %s deleted inside the grace period", x.Hex()[:8])
		}
	}
	// A fresh upload is inside the grace too, even with old index times.
	blob, x4, _ := buildXorb(t, payloadsOf('4', 1))
	if _, err := f.srv.IngestXorb(context.Background(), x4, bytes.NewReader(blob)); err != nil {
		t.Fatal(err)
	}
	f.srv.xorbMu.Lock()
	f.srv.xorbLastAccess[x4] = time.Now().Add(-48 * time.Hour)
	f.srv.xorbMu.Unlock()
	report, err = f.srv.Collect(context.Background(), GCOptions{Grace: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if !f.has(t, x4) || report.XorbsDeferred != 4 {
		t.Errorf("just-written xorb not protected by its mtime: has = %v, report = %+v", f.has(t, x4), report)
	}
}

func TestCollect_UnknownKeepOIDsAreReportedNotFatal(t *testing.T) {
	f := newGCFixture(t)
	f.backdate(t, 48*time.Hour)
	bogus := strings.Repeat("ab", 32)
	report, err := f.srv.Collect(context.Background(), GCOptions{Keep: []string{f.shaA, bogus, f.shaA, " "}})
	if err != nil {
		t.Fatal(err)
	}
	if report.KeepOIDs != 2 || report.KeepUnknown != 1 || len(report.KeepUnknownSample) != 1 || report.KeepUnknownSample[0] != bogus {
		t.Errorf("report = %+v", report)
	}
	if report.FilesKept != 1 || !f.has(t, f.x1) {
		t.Errorf("alice's file not kept: %+v", report)
	}
}

// noListStore is a Store with no optional capabilities at all.
type noListStore struct{ storage.Store }

func TestCollect_RefusesAStoreItCannotEnumerate(t *testing.T) {
	inner, err := fsstore.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := New(noListStore{inner})
	if _, err := srv.Collect(context.Background(), GCOptions{}); !errors.Is(err, ErrGCUnsupported) {
		t.Errorf("Collect() error = %v, want ErrGCUnsupported", err)
	}
	// A VerifyingStore over fsstore is looked through.
	srv = New(storage.NewVerifyingStore(inner))
	if _, err := srv.Collect(context.Background(), GCOptions{}); err != nil {
		t.Errorf("Collect() through VerifyingStore error = %v", err)
	}
}

func TestDedupAnswer_ExpiresAndMarksXorbsAccessed(t *testing.T) {
	f := newGCFixture(t)
	f.backdate(t, 48*time.Hour)
	before := time.Now()
	answer, known, _ := f.srv.dedupAnswer(f.chunkInXS)
	if !known {
		t.Fatal("shared chunk unknown")
	}
	shard, err := shardformat.ReadShard(bytes.NewReader(answer))
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Unix(int64(shard.Footer.ShardKeyExpiry), 0)
	lo, hi := before.Add(dedupAnswerTTL).Add(-time.Minute), before.Add(dedupAnswerTTL).Add(time.Minute)
	if expiry.Before(lo) || expiry.After(hi) {
		t.Errorf("ShardKeyExpiry = %v, want about %v", expiry, before.Add(dedupAnswerTTL))
	}
	f.srv.xorbMu.RLock()
	defer f.srv.xorbMu.RUnlock()
	for _, x := range shard.Xorbs {
		if f.srv.xorbLastAccess[x.Header.XorbHash].Before(before) {
			t.Errorf("xorb %s advertised but last access not updated", x.Header.XorbHash.Hex()[:8])
		}
	}
	if !f.srv.xorbLastAccess[f.x3].Before(before) {
		t.Error("orphan xorb's last access moved without being advertised")
	}
}

func TestSnapshot_PersistsLastAccess(t *testing.T) {
	f := newGCFixture(t)
	then := time.Now().Add(-72 * time.Hour).Round(0)
	f.srv.xorbMu.Lock()
	f.srv.xorbLastAccess[f.x1] = then
	f.srv.xorbMu.Unlock()
	snap := filepath.Join(f.dir, "snap.json")
	if err := f.srv.Snapshot(snap); err != nil {
		t.Fatal(err)
	}
	restarted := newFolderServer(t, f.dir)
	if err := restarted.LoadSnapshot(snap); err != nil {
		t.Fatal(err)
	}
	restarted.xorbMu.RLock()
	got := restarted.xorbLastAccess[f.x1]
	restarted.xorbMu.RUnlock()
	if !got.Equal(then) {
		t.Errorf("last access after restart = %v, want %v", got, then)
	}
}

// gcRequest posts body to the handler with the given Authorization.
func gcRequest(t *testing.T, ts *httptest.Server, authz string, body string) (*http.Response, GCReport) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+GCPath, strings.NewReader(body))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var report GCReport
	if resp.StatusCode == http.StatusOK {
		if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
			t.Fatal(err)
		}
	}
	return resp, report
}

func TestGCHandler_AdminOnlyExtraKeepAndAfterCollect(t *testing.T) {
	f := newGCFixture(t)
	f.backdate(t, 48*time.Hour)
	const secret = "gc-fixture-secret-not-a-real-credential"
	signed := auth.NewSignedTokenAuth(secret)
	f.srv.SetAuthenticator(signed)
	afterCalls := 0
	cfg := GCHandlerConfig{
		DefaultGrace: 0,
		ExtraKeep:    func() []string { return []string{f.shaB} },
		AfterCollect: func() error { afterCalls++; return nil },
	}
	mux := http.NewServeMux()
	mux.Handle("POST "+GCPath, f.srv.GCHandler(cfg))
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// A minted write token (what every client holds) is refused.
	minted, _, err := signed.MintToken(auth.ScopeWrite, "alice", auth.Repo{Type: "model", ID: "alice/gc"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := gcRequest(t, ts, "Bearer "+minted, `{"keep":[]}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("minted token: status %d, want 403", resp.StatusCode)
	}
	if resp, _ := gcRequest(t, ts, "", `{"keep":[]}`); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no credential: status %d, want 401", resp.StatusCode)
	}
	if f.has(t, f.x3) != true {
		t.Fatal("a refused request deleted something")
	}

	// The secret: a dry run reports, calls nothing, deletes nothing.
	resp, report := gcRequest(t, ts, "Bearer "+secret, `{"keep":["`+f.shaA+`"],"dry_run":true}`)
	if resp.StatusCode != http.StatusOK || !report.DryRun || report.FilesKept != 2 || report.XorbsDeleted != 1 {
		t.Errorf("dry run: status %d, report %+v (want both files kept, orphan to delete)", resp.StatusCode, report)
	}
	if afterCalls != 0 || !f.has(t, f.x3) {
		t.Errorf("dry run had effects: afterCalls = %d, orphan present = %v", afterCalls, f.has(t, f.x3))
	}
	// A real run through the Basic form git-lfs uses; ExtraKeep keeps
	// bob's file though the request only names alice's.
	req, _ := http.NewRequest(http.MethodPost, ts.URL+GCPath, strings.NewReader(`{"keep":["`+f.shaA+`"]}`))
	req.SetBasicAuth("operator", secret)
	realResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer realResp.Body.Close()
	if err := json.NewDecoder(realResp.Body).Decode(&report); err != nil || realResp.StatusCode != http.StatusOK {
		t.Fatalf("real run: status %d, err %v", realResp.StatusCode, err)
	}
	if report.FilesKept != 2 || report.XorbsDeleted != 1 || f.has(t, f.x3) || !f.has(t, f.x2) {
		t.Errorf("real run: report %+v, orphan present = %v, X2 present = %v", report, f.has(t, f.x3), f.has(t, f.x2))
	}
	if afterCalls != 1 {
		t.Errorf("AfterCollect called %d times, want 1", afterCalls)
	}
	// Grace from the request overrides the default (everything here is
	// two days old, so a day of grace defers nothing but is reported).
	resp, report = gcRequest(t, ts, "Bearer "+secret, `{"keep":[],"grace_seconds":86400,"dry_run":true}`)
	if resp.StatusCode != http.StatusOK || report.GraceSeconds != 86400 || report.FilesDropped != 1 || report.FilesKept != 1 {
		t.Errorf("grace override: status %d, report %+v", resp.StatusCode, report)
	}
	if resp, _ := gcRequest(t, ts, "Bearer "+secret, `not json`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad body: status %d, want 400", resp.StatusCode)
	}

	// Disabled (synced-folder mode) refuses even the secret.
	disabled := httptest.NewServer(f.srv.GCHandler(GCHandlerConfig{Disabled: "sync-folder"}))
	defer disabled.Close()
	if resp, _ := gcRequest(t, disabled, "Bearer "+secret, `{"keep":[]}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("disabled: status %d, want 409", resp.StatusCode)
	}
}

// TestCollect_RecentShardsKeepTheirFiles: a file whose shard arrived
// inside the grace period is kept although no keep list names it - the
// window between an LFS object upload and the git push that makes its
// pointer visible to `git lfs ls-files`.
func TestCollect_RecentShardsKeepTheirFiles(t *testing.T) {
	f := newGCFixture(t)
	f.backdate(t, 48*time.Hour)
	shaC, fileC, contentC, xc := pushComposite(t, f.srv, []filePart{{payloadsOf('c', 2), true}})
	report, err := f.srv.Collect(context.Background(), GCOptions{Keep: []string{f.shaA}, Grace: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesKept != 2 || report.FilesRecent != 1 || report.FilesDropped != 1 {
		t.Errorf("report = %+v, want A kept by the list, C kept as recent, B dropped", report)
	}
	if _, ok := f.srv.XetHashForSHA256(shaC); !ok || !f.has(t, xc[0]) {
		t.Fatal("the in-progress push lost its file or xorb")
	}
	if out, err := reconstruct(t, f.srv, fileC, len(contentC)); err != nil || !bytes.Equal(out, contentC) {
		t.Errorf("file C: err = %v", err)
	}
	// Once the shard is older than the grace and still unlisted, it goes.
	f.backdate(t, 48*time.Hour)
	report, err = f.srv.Collect(context.Background(), GCOptions{Keep: []string{f.shaA}, Grace: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesRecent != 0 || report.FilesDropped != 1 || f.has(t, xc[0]) {
		t.Errorf("second run: report = %+v, C's xorb present = %v", report, f.has(t, xc[0]))
	}
}

// TestCollect_DoesNotRaceUploads runs a collection while shards and
// xorbs are being ingested; nothing ingested may be lost or half-indexed.
func TestCollect_DoesNotRaceUploads(t *testing.T) {
	f := newGCFixture(t)
	f.backdate(t, 48*time.Hour)
	done := make(chan struct{})
	type pushed struct {
		sha     string
		file    merklehash.Hash
		content []byte
	}
	results := make(chan pushed, 8)
	go func() {
		defer close(done)
		for i := 0; i < 8; i++ {
			sha, file, content, _ := pushComposite(t, f.srv, []filePart{{payloadsOf(byte('a'+i), 3), true}})
			results <- pushed{sha, file, content}
		}
	}()
	for i := 0; i < 4; i++ {
		if _, err := f.srv.Collect(context.Background(), GCOptions{Keep: []string{f.shaA}, Grace: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}
	<-done
	close(results)
	for p := range results {
		if h, ok := f.srv.XetHashForSHA256(p.sha); !ok || h != p.file {
			t.Errorf("file pushed during gc lost its sha256 mapping")
		}
		if out, err := reconstruct(t, f.srv, p.file, len(p.content)); err != nil || !bytes.Equal(out, p.content) {
			t.Errorf("file pushed during gc: err = %v", err)
		}
	}
}
