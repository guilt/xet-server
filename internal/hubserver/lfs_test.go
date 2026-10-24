package hubserver

// lfs_test.go covers the git-lfs face of this server (lfs.go,
// lfsbatch.go, lfsobjects.go, lfslocks.go) against the fake CAS: the
// exact batch shapes git-lfs and git-xet need, the download bridge with
// Range, the locking API, and the auth challenge git-lfs relies on.
// Every secret is a hardcoded test fixture, not a real credential.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/merklehash"
)

const lfsFixtureSecret = "lfs-fixture-secret-not-a-real-credential"

// storeFile registers content in the fake CAS the way a real shard
// upload would: SHA-256 -> Xet hash -> size and bytes.
func (f *fakeCAS) storeFile(content []byte) (oid string) {
	sum := sha256.Sum256(content)
	oid = hex.EncodeToString(sum[:])
	xet := merklehash.ComputeDataHash(content)
	f.sha256ToXet[oid] = xet
	f.sizes[xet] = int64(len(content))
	f.content[xet] = content
	return oid
}

func newLFSTestServer(t *testing.T) (*httptest.Server, *fakeCAS, *auth.SignedTokenAuth) {
	t.Helper()
	cas := newFakeCAS()
	a := auth.NewSignedTokenAuth(lfsFixtureSecret)
	hubSrv := New("http://cas.example:8420", cas)
	hubSrv.SetAuthenticator(a)
	hubSrv.SetTokenMinter(a)
	ts := httptest.NewServer(hubSrv)
	t.Cleanup(ts.Close)
	return ts, cas, a
}

// lfsDo sends a git-lfs style request as user with the shared secret via
// Basic auth (what git-lfs does after a 401), or unauthenticated if user
// is empty.
func lfsDo(t *testing.T, ts *httptest.Server, method, path, user string, body string) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept", lfsMediaType)
	if body != "" {
		req.Header.Set("Content-Type", lfsMediaType)
	}
	if user != "" {
		req.SetBasicAuth(user, lfsFixtureSecret)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

const batchPath = "/team/game.git/info/lfs/objects/batch"

func TestLFSBatch_UnauthenticatedGets401WithChallenge(t *testing.T) {
	ts, _, _ := newLFSTestServer(t)
	resp, body := lfsDo(t, ts, http.MethodPost, batchPath, "", `{"operation":"upload","transfers":["basic","xet"],"objects":[]}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("LFS-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Errorf("LFS-Authenticate = %q, want a Basic challenge", got)
	}
	if ct := resp.Header.Get("Content-Type"); ct != lfsMediaType {
		t.Errorf("Content-Type = %q, want %q", ct, lfsMediaType)
	}
	var e lfsErrorBody
	if err := json.Unmarshal(body, &e); err != nil || e.Message == "" {
		t.Errorf("body %q is not a {message} error", body)
	}
}

func TestLFSBatch_UploadWithXetReturnsTokenActions(t *testing.T) {
	ts, cas, a := newLFSTestServer(t)
	stored := cas.storeFile([]byte("already here"))
	fresh := strings.Repeat("ab", 32)

	reqBody := `{"operation":"upload","transfers":["basic","xet"],"ref":{"name":"refs/heads/feature"},` +
		`"objects":[{"oid":"` + fresh + `","size":10},{"oid":"` + stored + `","size":12},{"oid":"BAD","size":1}],"hash_algo":"sha256"}`
	resp, body := lfsDo(t, ts, http.MethodPost, batchPath, "alice", reqBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != lfsMediaType {
		t.Errorf("Content-Type = %q", ct)
	}
	var out lfsBatchResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Transfer != "xet" || out.HashAlgo != "sha256" || len(out.Objects) != 3 {
		t.Fatalf("transfer=%q hash_algo=%q objects=%d", out.Transfer, out.HashAlgo, len(out.Objects))
	}

	// Object 0: fresh, needs the xet upload action git-xet reads.
	o := out.Objects[0]
	if o.Error != nil || !o.Authenticated {
		t.Fatalf("fresh object: error=%v authenticated=%v", o.Error, o.Authenticated)
	}
	up := o.Actions["upload"]
	if up == nil {
		t.Fatal("fresh object lacks an upload action")
	}
	if want := ts.URL + "/api/models/team/game/xet-write-token/feature"; up.Href != want {
		t.Errorf("href = %q, want %q", up.Href, want)
	}
	if up.Header[headerXetCasURL] != "http://cas.example:8420" {
		t.Errorf("%s = %q", headerXetCasURL, up.Header[headerXetCasURL])
	}
	if up.Header[headerXetSessionID] == "" || up.Header[headerXetTokenExpiration] == "" {
		t.Error("session id / expiration headers missing")
	}
	if up.ExpiresIn != 0 {
		t.Error("xet upload action must not carry expires_in (git-xet refreshes its own token)")
	}
	// The minted token must verify as a write token for alice on the CAS side.
	r, _ := http.NewRequest(http.MethodGet, "http://cas/", nil)
	r.Header.Set("Authorization", "Bearer "+up.Header[headerXetAccessToken])
	p, err := a.Authenticate(r)
	if err != nil || !p.HasScope(auth.ScopeWrite) || p.Subject() != "alice" {
		t.Errorf("minted token: err=%v principal=%v", err, p)
	}

	// Object 1: already stored, so no actions (git-lfs skips it).
	if o := out.Objects[1]; o.Actions != nil || o.Error != nil {
		t.Errorf("stored object: actions=%v error=%v, want neither", o.Actions, o.Error)
	}
	// Object 2: bad oid is a per-object 422, not a failed batch.
	if o := out.Objects[2]; o.Error == nil || o.Error.Code != http.StatusUnprocessableEntity {
		t.Errorf("bad oid: error=%v, want 422", o.Error)
	}

	// The token refresh route git-xet calls must accept the same Basic
	// credential and return the JSON shape CasJWTInfo expects.
	resp, body = lfsDo(t, ts, http.MethodGet, "/api/models/team/game/xet-write-token/feature", "alice", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token route status = %d, body %s", resp.StatusCode, body)
	}
	var tok xetTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil || tok.CasURL == "" || tok.AccessToken == "" || tok.Exp == 0 {
		t.Errorf("token route body %s is not a CasJWTInfo", body)
	}
}

func TestLFSBatch_UploadWithoutXetIsAClearPerObjectError(t *testing.T) {
	ts, _, _ := newLFSTestServer(t)
	resp, body := lfsDo(t, ts, http.MethodPost, batchPath, "alice",
		`{"operation":"upload","transfers":["basic"],"objects":[{"oid":"`+strings.Repeat("ab", 32)+`","size":10}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	var out lfsBatchResponse
	json.Unmarshal(body, &out)
	if out.Transfer != "basic" {
		t.Errorf("transfer = %q, want basic", out.Transfer)
	}
	if o := out.Objects[0]; o.Error == nil || !strings.Contains(o.Error.Message, "git-xet") {
		t.Errorf("object error = %v, want a hint to install git-xet", o.Error)
	}
}

func TestLFSBatch_DownloadReturnsBasicHrefsAnd404PerMissingObject(t *testing.T) {
	ts, cas, a := newLFSTestServer(t)
	content := []byte("the quick brown fox")
	oid := cas.storeFile(content)
	missing := strings.Repeat("cd", 32)

	resp, body := lfsDo(t, ts, http.MethodPost, batchPath, "bob",
		`{"operation":"download","transfers":["basic","xet"],"objects":[{"oid":"`+oid+`","size":19},{"oid":"`+missing+`","size":5},{"oid":"`+oid+`","size":3}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	var out lfsBatchResponse
	json.Unmarshal(body, &out)
	if out.Transfer != "basic" {
		t.Fatalf("transfer = %q, want basic (git-xet cannot download)", out.Transfer)
	}
	dl := out.Objects[0].Actions["download"]
	if dl == nil {
		t.Fatal("stored object lacks a download action")
	}
	if want := ts.URL + "/team/game.git/info/lfs/objects/" + oid; dl.Href != want {
		t.Errorf("href = %q, want %q", dl.Href, want)
	}
	tokenHeader := dl.Header["Authorization"]
	if !strings.HasPrefix(tokenHeader, "Bearer ") {
		t.Fatalf("Authorization header = %q", tokenHeader)
	}
	r, _ := http.NewRequest(http.MethodGet, "http://cas/", nil)
	r.Header.Set("Authorization", tokenHeader)
	if p, err := a.Authenticate(r); err != nil || p.HasScope(auth.ScopeWrite) || !p.HasScope(auth.ScopeRead) {
		t.Errorf("download token should be read-only: err=%v", err)
	}
	if o := out.Objects[1]; o.Error == nil || o.Error.Code != http.StatusNotFound {
		t.Errorf("missing object error = %v, want per-object 404", o.Error)
	}
	if o := out.Objects[2]; o.Error == nil || o.Error.Code != http.StatusUnprocessableEntity {
		t.Errorf("size-mismatch error = %v, want 422", o.Error)
	}

	// Follow the href exactly as git-lfs would: the action header alone
	// authenticates, and the bytes come back whole with a Content-Length.
	req, _ := http.NewRequest(http.MethodGet, dl.Href, nil)
	req.Header.Set("Authorization", tokenHeader)
	getResp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer getResp.Body.Close()
	got, _ := io.ReadAll(getResp.Body)
	if getResp.StatusCode != http.StatusOK || !bytes.Equal(got, content) {
		t.Fatalf("GET href: status %d body %q", getResp.StatusCode, got)
	}
	if cl := getResp.Header.Get("Content-Length"); cl != "19" {
		t.Errorf("Content-Length = %q, want 19", cl)
	}
}

func TestLFSObject_RangeResumeHeadAndErrors(t *testing.T) {
	ts, cas, _ := newLFSTestServer(t)
	content := []byte("0123456789abcdefghij")
	oid := cas.storeFile(content)
	path := "/team/game.git/info/lfs/objects/" + oid

	get := func(rangeHeader string, method string) (*http.Response, []byte) {
		req, _ := http.NewRequest(method, ts.URL+path, nil)
		req.SetBasicAuth("bob", lfsFixtureSecret)
		if rangeHeader != "" {
			req.Header.Set("Range", rangeHeader)
		}
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b
	}

	// Resume from byte 15: git-lfs sends an open-ended range.
	resp, body := get("bytes=15-", http.MethodGet)
	if resp.StatusCode != http.StatusPartialContent || string(body) != "fghij" {
		t.Errorf("resume: status %d body %q", resp.StatusCode, body)
	}
	if cr := resp.Header.Get("Content-Range"); cr != "bytes 15-19/20" {
		t.Errorf("Content-Range = %q", cr)
	}
	// Closed range, clipped at the end.
	resp, body = get("bytes=2-100", http.MethodGet)
	if resp.StatusCode != http.StatusPartialContent || string(body) != "23456789abcdefghij" {
		t.Errorf("closed range: status %d body %q", resp.StatusCode, body)
	}
	// Unsatisfiable start.
	resp, _ = get("bytes=20-", http.MethodGet)
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("past-end range: status %d, want 416", resp.StatusCode)
	}
	// HEAD reports size without a body.
	resp, body = get("", http.MethodHead)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Length") != "20" || len(body) != 0 {
		t.Errorf("HEAD: status %d length %q body %d bytes", resp.StatusCode, resp.Header.Get("Content-Length"), len(body))
	}
	// Unknown oid is a 404 with an LFS message.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/team/game.git/info/lfs/objects/"+strings.Repeat("ee", 32), nil)
	req.SetBasicAuth("bob", lfsFixtureSecret)
	r404, _ := ts.Client().Do(req)
	r404.Body.Close()
	if r404.StatusCode != http.StatusNotFound {
		t.Errorf("unknown oid: status %d, want 404", r404.StatusCode)
	}
	// No credential at all: 401 with the challenge.
	req, _ = http.NewRequest(http.MethodGet, ts.URL+path, nil)
	r401, _ := ts.Client().Do(req)
	r401.Body.Close()
	if r401.StatusCode != http.StatusUnauthorized || r401.Header.Get("LFS-Authenticate") == "" {
		t.Errorf("unauthenticated: status %d challenge %q", r401.StatusCode, r401.Header.Get("LFS-Authenticate"))
	}
}

func TestLFSLocks_Lifecycle(t *testing.T) {
	ts, _, _ := newLFSTestServer(t)
	lockLifecycle(t, ts)
}

// The same lifecycle against locks stored as files in a directory (the
// synced-folder store); the HTTP contract must not differ.
func TestLFSLocks_LifecycleOnFolderStore(t *testing.T) {
	cas := newFakeCAS()
	a := auth.NewSignedTokenAuth(lfsFixtureSecret)
	hubSrv := New("http://cas.example:8420", cas)
	hubSrv.SetAuthenticator(a)
	hubSrv.SetTokenMinter(a)
	if err := hubSrv.SetLockDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(hubSrv)
	t.Cleanup(ts.Close)
	lockLifecycle(t, ts)
}

func lockLifecycle(t *testing.T, ts *httptest.Server) {
	t.Helper()
	locks := "/team/game.git/info/lfs/locks"

	// Alice locks a scene.
	resp, body := lfsDo(t, ts, http.MethodPost, locks, "alice", `{"path":"Assets/Scenes/Main.unity","ref":{"name":"refs/heads/main"}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: status %d body %s", resp.StatusCode, body)
	}
	var created struct {
		Lock lfsLock `json:"lock"`
	}
	json.Unmarshal(body, &created)
	if created.Lock.ID == "" || created.Lock.Owner.Name != "alice" || created.Lock.Path != "Assets/Scenes/Main.unity" {
		t.Fatalf("created lock = %+v", created.Lock)
	}
	if _, err := time.Parse(time.RFC3339, created.Lock.LockedAt); err != nil {
		t.Errorf("locked_at %q is not RFC 3339", created.Lock.LockedAt)
	}

	// Bob cannot lock the same path: 409 carrying the existing lock.
	resp, body = lfsDo(t, ts, http.MethodPost, locks, "bob", `{"path":"Assets/Scenes/Main.unity"}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("conflict: status %d body %s", resp.StatusCode, body)
	}
	var conflict struct {
		Lock    lfsLock `json:"lock"`
		Message string  `json:"message"`
	}
	json.Unmarshal(body, &conflict)
	if conflict.Lock.ID != created.Lock.ID || conflict.Message == "" {
		t.Errorf("conflict body = %s", body)
	}

	// Bob locks something else; listing shows both, filtering by path shows one.
	lfsDo(t, ts, http.MethodPost, locks, "bob", `{"path":"Assets/Prefabs/Player.prefab"}`)
	resp, body = lfsDo(t, ts, http.MethodGet, locks, "bob", "")
	var listed struct {
		Locks      []lfsLock `json:"locks"`
		NextCursor string    `json:"next_cursor"`
	}
	json.Unmarshal(body, &listed)
	if resp.StatusCode != http.StatusOK || len(listed.Locks) != 2 {
		t.Fatalf("list: status %d locks %d", resp.StatusCode, len(listed.Locks))
	}
	_, body = lfsDo(t, ts, http.MethodGet, locks+"?path=Assets/Prefabs/Player.prefab", "bob", "")
	json.Unmarshal(body, &listed)
	if len(listed.Locks) != 1 || listed.Locks[0].Owner.Name != "bob" {
		t.Errorf("filtered list = %s", body)
	}
	// Paging: limit 1 yields a cursor, following it yields the rest.
	_, body = lfsDo(t, ts, http.MethodGet, locks+"?limit=1", "bob", "")
	json.Unmarshal(body, &listed)
	if len(listed.Locks) != 1 || listed.NextCursor == "" {
		t.Fatalf("page 1 = %s", body)
	}
	_, body = lfsDo(t, ts, http.MethodGet, locks+"?limit=1&cursor="+listed.NextCursor, "bob", "")
	var page2 struct {
		Locks      []lfsLock `json:"locks"`
		NextCursor string    `json:"next_cursor"`
	}
	json.Unmarshal(body, &page2)
	if len(page2.Locks) != 1 || page2.NextCursor != "" || page2.Locks[0].ID == listed.Locks[0].ID {
		t.Fatalf("page 2 = %s", body)
	}

	// Verify splits ours/theirs by the caller's identity.
	resp, body = lfsDo(t, ts, http.MethodPost, locks+"/verify", "bob", `{"ref":{"name":"refs/heads/main"}}`)
	var verify struct {
		Ours   []lfsLock `json:"ours"`
		Theirs []lfsLock `json:"theirs"`
	}
	json.Unmarshal(body, &verify)
	if resp.StatusCode != http.StatusOK || len(verify.Ours) != 1 || len(verify.Theirs) != 1 || verify.Theirs[0].Owner.Name != "alice" {
		t.Fatalf("verify: status %d body %s", resp.StatusCode, body)
	}
	// An empty body is fine too (git-lfs may send none).
	resp, _ = lfsDo(t, ts, http.MethodPost, locks+"/verify", "bob", "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("verify with empty body: status %d", resp.StatusCode)
	}

	// Bob cannot unlock alice's lock without force; with force he can.
	unlock := locks + "/" + created.Lock.ID + "/unlock"
	resp, _ = lfsDo(t, ts, http.MethodPost, unlock, "bob", `{}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unlock other's lock: status %d, want 403", resp.StatusCode)
	}
	resp, body = lfsDo(t, ts, http.MethodPost, unlock, "bob", `{"force":true}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("force unlock: status %d body %s", resp.StatusCode, body)
	}
	resp, _ = lfsDo(t, ts, http.MethodPost, unlock, "bob", `{}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unlock twice: status %d, want 404", resp.StatusCode)
	}
	// Alice can now lock the path again.
	resp, _ = lfsDo(t, ts, http.MethodPost, locks, "alice", `{"path":"Assets/Scenes/Main.unity"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("relock: status %d", resp.StatusCode)
	}
	// Listing needs only read access; creating needs write: a read token holder is refused.
	resp, _ = lfsDo(t, ts, http.MethodPost, locks, "", `{"path":"x"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated create: status %d, want 401", resp.StatusCode)
	}
}

func TestLFSLocks_SurviveSnapshot(t *testing.T) {
	cas := newFakeCAS()
	hubSrv := New("http://cas.example:8420", cas)
	ts := httptest.NewServer(hubSrv)
	defer ts.Close()

	resp, body := lfsDo(t, ts, http.MethodPost, "/team/game.git/info/lfs/locks", "", `{"path":"big.psd"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	path := t.TempDir() + "/hub.json"
	if err := hubSrv.Snapshot(path); err != nil {
		t.Fatal(err)
	}
	restored := New("http://cas.example:8420", cas)
	if err := restored.LoadSnapshot(path); err != nil {
		t.Fatal(err)
	}
	ts2 := httptest.NewServer(restored)
	defer ts2.Close()
	_, body = lfsDo(t, ts2, http.MethodGet, "/team/game.git/info/lfs/locks", "", "")
	var listed struct {
		Locks []lfsLock `json:"locks"`
	}
	json.Unmarshal(body, &listed)
	if len(listed.Locks) != 1 || listed.Locks[0].Path != "big.psd" {
		t.Fatalf("restored locks = %s", body)
	}
}

func TestSplitLFSPath(t *testing.T) {
	cases := []struct {
		rest, repoType, repo, endpoint string
		ok                             bool
	}{
		{"team/game.git/info/lfs/objects/batch", "model", "team/game", "objects/batch", true},
		{"datasets/team/game.git/info/lfs/locks/verify", "dataset", "team/game", "locks/verify", true},
		{"team/game.git/info/lfs", "model", "team/game", "", true},
		{"game.git/info/lfs/objects/batch", "", "", "", false},
		{"/.git/info/lfs/objects/batch", "", "", "", false},
		{"team/game/resolve/main/x", "", "", "", false},
	}
	for _, c := range cases {
		repoType, repo, ep, ok := splitLFSPath(c.rest)
		if ok != c.ok || repoType != c.repoType || repo != c.repo || ep != c.endpoint {
			t.Errorf("splitLFSPath(%q) = %q, %q, %q, %v; want %q, %q, %q, %v", c.rest, repoType, repo, ep, ok, c.repoType, c.repo, c.endpoint, c.ok)
		}
	}
}

func TestParseLFSRange(t *testing.T) {
	cases := []struct {
		header     string
		start, end int64
		has, isErr bool
	}{
		{"", 0, 0, false, false},
		{"bytes=0-9", 0, 9, true, false},
		{"bytes=5-", 5, 99, true, false},
		{"bytes=5-500", 5, 99, true, false},
		{"bytes=-10", 90, 99, true, false},
		{"bytes=100-", 0, 0, false, true},
		{"bytes=abc", 0, 0, false, false},
		{"bytes=0-1,5-6", 0, 0, false, false},
		{"items=0-1", 0, 0, false, false},
	}
	for _, c := range cases {
		s, e, has, err := parseLFSRange(c.header, 100)
		if (err != nil) != c.isErr || has != c.has || (has && (s != c.start || e != c.end)) {
			t.Errorf("parseLFSRange(%q) = %d, %d, %v, %v; want %d, %d, %v, err=%v", c.header, s, e, has, err, c.start, c.end, c.has, c.isErr)
		}
	}
}

// On a synced folder a file's shard can arrive before its xorbs. The
// batch answers 503 per object and the object route refuses before the
// first byte, so git-lfs reports "retry later", not a checksum failure.
func TestLFSDownload_UnavailableWhileXorbsSync(t *testing.T) {
	ts, cas, _ := newLFSTestServer(t)
	content := []byte("arrives later")
	oid := cas.storeFile(content)
	xet := cas.sha256ToXet[oid]
	cas.missing[xet] = []merklehash.Hash{merklehash.ComputeDataHash([]byte("xorb"))}

	resp, body := lfsDo(t, ts, http.MethodPost, batchPath, "bob",
		`{"operation":"download","transfers":["basic"],"objects":[{"oid":"`+oid+`","size":13}]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("batch status %d", resp.StatusCode)
	}
	var out lfsBatchResponse
	json.Unmarshal(body, &out)
	if len(out.Objects) != 1 || out.Objects[0].Error == nil || out.Objects[0].Error.Code != http.StatusServiceUnavailable || out.Objects[0].Actions != nil {
		t.Fatalf("batch object = %s; want a 503 error and no download action", body)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/team/game.git/info/lfs/objects/"+oid, nil)
	req.SetBasicAuth("bob", lfsFixtureSecret)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("object route: %d, Retry-After %q; want 503 with Retry-After", resp.StatusCode, resp.Header.Get("Retry-After"))
	}

	// Once the xorbs land, the same requests succeed.
	delete(cas.missing, xet)
	resp, body = lfsDo(t, ts, http.MethodPost, batchPath, "bob",
		`{"operation":"download","transfers":["basic"],"objects":[{"oid":"`+oid+`","size":13}]}`)
	var after lfsBatchResponse // fresh: Unmarshal into out would keep the old Error
	json.Unmarshal(body, &after)
	if after.Objects[0].Error != nil || after.Objects[0].Actions["download"] == nil {
		t.Fatalf("after sync batch object = %s", body)
	}
}
