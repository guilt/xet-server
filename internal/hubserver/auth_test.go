package hubserver

// Auth wiring tests: scope enforcement per route, backward compatibility (a
// Server constructed the old way - no SetAuthenticator call - must behave
// identically to before v0.8.0), and adversarial Authorization headers.
// Mirrors internal/casserver/auth_test.go's structure and conventions.
//
// Every token string below (e.g. "test-fixture-token-not-a-real-secret") is
// a hardcoded test fixture with no relation to any real credential -
// flagged explicitly so static-analysis secret scanners don't need to
// guess.

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/merklehash"
)

// testFixtureToken is the shared-secret value every test in this file
// configures StaticTokenAuth with. Not a real credential of any kind - just
// a fixed string two test helpers need to agree on.
const testFixtureToken = "test-fixture-token-not-a-real-secret"

// newAuthTestServer is like newTestServer but with a StaticTokenAuth
// installed via SetAuthenticator, for tests exercising 401/403 behavior.
func newAuthTestServer(t *testing.T, token string) (*httptest.Server, *fakeCAS) {
	t.Helper()
	cas := newFakeCAS()
	hubSrv := New("http://localhost:9999", cas)
	hubSrv.SetAuthenticator(auth.NewStaticTokenAuth(token))
	ts := httptest.NewServer(hubSrv)
	t.Cleanup(ts.Close)
	return ts, cas
}

// doWithAuth sends method/url with bearerHeader as the raw Authorization
// header value (skipped entirely if empty). Returns ok=false if net/http's
// own client rejected the header before ever sending the request (e.g. a
// value containing a raw control character or CRLF) - callers should treat
// that as an acceptable outcome for adversarial input, the same as a clean
// 401 from the server, since either way the malformed credential never
// reached (or succeeded against) the server.
func doWithAuth(t *testing.T, method, url, bearerHeader string, body io.Reader) (resp *http.Response, ok bool) {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	if bearerHeader != "" {
		req.Header.Set("Authorization", bearerHeader)
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "invalid header field value") {
			return nil, false
		}
		t.Fatalf("%s %s error = %v", method, url, err)
	}
	return resp, true
}

func TestAuth_BackwardCompat_DefaultServerNeverConstructedWithSetAuthenticator(t *testing.T) {
	// The regression guard for "keep current implementation working as is":
	// a Server built exactly the way every pre-v0.8.0 caller already does
	// (New(casBaseURL, cas), no SetAuthenticator call at all) must accept
	// every request with zero Authorization header, across repo-create,
	// token issuance, commit, and resolve.
	ts, _ := newTestServer(t)

	createResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/repos/create", "", strings.NewReader(`{"name":"my-model","organization":"alice","type":"model"}`))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	createResp.Body.Close()
	if createResp.StatusCode != http.StatusOK {
		t.Errorf("repo-create status = %d, want 200 with no auth configured", createResp.StatusCode)
	}

	tokenResp, ok := doWithAuth(t, http.MethodGet, ts.URL+"/api/models/alice/my-model/xet-read-token/main", "", nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Errorf("xet-read-token status = %d, want 200 with no auth configured", tokenResp.StatusCode)
	}

	ndjson := `{"key":"lfsFile","value":{"path":"model.bin","algo":"sha256","oid":"abc123","size":500000}}` + "\n"
	commitResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/models/alice/my-model/commit/main", "", strings.NewReader(ndjson))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	commitResp.Body.Close()
	if commitResp.StatusCode != http.StatusOK {
		t.Errorf("commit status = %d, want 200 with no auth configured", commitResp.StatusCode)
	}

	resolveResp, ok := doWithAuth(t, http.MethodHead, ts.URL+"/alice/my-model/resolve/main/never-uploaded.bin", "", nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	resolveResp.Body.Close()
	if resolveResp.StatusCode != http.StatusNotFound {
		t.Errorf("resolve (unknown file) status = %d, want 404 with no auth configured", resolveResp.StatusCode)
	}
}

func TestAuth_RepoCreateAndCommit_RequireWriteToken(t *testing.T) {
	ts, _ := newAuthTestServer(t, testFixtureToken)

	noTokenResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/repos/create", "", strings.NewReader(`{"name":"my-model","organization":"alice","type":"model"}`))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	noTokenResp.Body.Close()
	if noTokenResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token repo-create status = %d, want 401", noTokenResp.StatusCode)
	}

	// "wrong-fixture-token": deliberately incorrect, not a real credential.
	wrongTokenResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/repos/create", "Bearer wrong-fixture-token", strings.NewReader(`{"name":"my-model","organization":"alice","type":"model"}`))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	wrongTokenResp.Body.Close()
	if wrongTokenResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong-token repo-create status = %d, want 401", wrongTokenResp.StatusCode)
	}

	correctResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/repos/create", "Bearer "+testFixtureToken, strings.NewReader(`{"name":"my-model","organization":"alice","type":"model"}`))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	defer correctResp.Body.Close()
	if correctResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(correctResp.Body)
		t.Errorf("correct-token repo-create status = %d, want 200; body = %s", correctResp.StatusCode, body)
	}

	ndjson := `{"key":"lfsFile","value":{"path":"model.bin","algo":"sha256","oid":"abc123","size":500000}}` + "\n"
	noTokenCommitResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/models/alice/my-model/commit/main", "", strings.NewReader(ndjson))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	noTokenCommitResp.Body.Close()
	if noTokenCommitResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token commit status = %d, want 401", noTokenCommitResp.StatusCode)
	}

	correctCommitResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/models/alice/my-model/commit/main", "Bearer "+testFixtureToken, strings.NewReader(ndjson))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	defer correctCommitResp.Body.Close()
	if correctCommitResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(correctCommitResp.Body)
		t.Errorf("correct-token commit status = %d, want 200; body = %s", correctCommitResp.StatusCode, body)
	}
}

func TestAuth_XetTokenEndpoints_RequireMatchingScope(t *testing.T) {
	ts, _ := newAuthTestServer(t, testFixtureToken)

	noTokenReadResp, ok := doWithAuth(t, http.MethodGet, ts.URL+"/api/models/alice/my-model/xet-read-token/main", "", nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	noTokenReadResp.Body.Close()
	if noTokenReadResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token xet-read-token status = %d, want 401", noTokenReadResp.StatusCode)
	}

	correctReadResp, ok := doWithAuth(t, http.MethodGet, ts.URL+"/api/models/alice/my-model/xet-read-token/main", "Bearer "+testFixtureToken, nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	correctReadResp.Body.Close()
	if correctReadResp.StatusCode != http.StatusOK {
		t.Errorf("correct-token xet-read-token status = %d, want 200", correctReadResp.StatusCode)
	}

	noTokenWriteResp, ok := doWithAuth(t, http.MethodGet, ts.URL+"/api/models/alice/my-model/xet-write-token/main", "", nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	noTokenWriteResp.Body.Close()
	if noTokenWriteResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token xet-write-token status = %d, want 401", noTokenWriteResp.StatusCode)
	}

	correctWriteResp, ok := doWithAuth(t, http.MethodGet, ts.URL+"/api/models/alice/my-model/xet-write-token/main", "Bearer "+testFixtureToken, nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	correctWriteResp.Body.Close()
	if correctWriteResp.StatusCode != http.StatusOK {
		t.Errorf("correct-token xet-write-token status = %d, want 200", correctWriteResp.StatusCode)
	}
}

func TestAuth_Preupload_RequiresWriteToken(t *testing.T) {
	ts, _ := newAuthTestServer(t, testFixtureToken)

	body := `{"files":[{"path":"model.bin","size":10}]}`
	noTokenResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/models/alice/my-model/preupload/main", "", strings.NewReader(body))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	noTokenResp.Body.Close()
	if noTokenResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token preupload status = %d, want 401", noTokenResp.StatusCode)
	}

	correctResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/models/alice/my-model/preupload/main", "Bearer "+testFixtureToken, strings.NewReader(body))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	defer correctResp.Body.Close()
	if correctResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(correctResp.Body)
		t.Errorf("correct-token preupload status = %d, want 200; body = %s", correctResp.StatusCode, respBody)
	}
}

func TestAuth_RepoInfoAndTree_RequireReadToken(t *testing.T) {
	ts, _ := newAuthTestServer(t, testFixtureToken)

	createResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/repos/create", "Bearer "+testFixtureToken, strings.NewReader(`{"name":"my-model","organization":"alice","type":"model"}`))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	createResp.Body.Close()

	noTokenInfoResp, ok := doWithAuth(t, http.MethodGet, ts.URL+"/api/models/alice/my-model/revision/main", "", nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	noTokenInfoResp.Body.Close()
	if noTokenInfoResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token revision-info status = %d, want 401", noTokenInfoResp.StatusCode)
	}

	correctInfoResp, ok := doWithAuth(t, http.MethodGet, ts.URL+"/api/models/alice/my-model/revision/main", "Bearer "+testFixtureToken, nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	correctInfoResp.Body.Close()
	if correctInfoResp.StatusCode != http.StatusOK {
		t.Errorf("correct-token revision-info status = %d, want 200", correctInfoResp.StatusCode)
	}

	noTokenTreeResp, ok := doWithAuth(t, http.MethodGet, ts.URL+"/api/models/alice/my-model/tree/main", "", nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	noTokenTreeResp.Body.Close()
	if noTokenTreeResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token tree status = %d, want 401", noTokenTreeResp.StatusCode)
	}

	correctTreeResp, ok := doWithAuth(t, http.MethodGet, ts.URL+"/api/models/alice/my-model/tree/main", "Bearer "+testFixtureToken, nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	correctTreeResp.Body.Close()
	if correctTreeResp.StatusCode != http.StatusOK {
		t.Errorf("correct-token tree status = %d, want 200", correctTreeResp.StatusCode)
	}
}

func TestAuth_CreateBranch_RequiresWriteToken(t *testing.T) {
	ts, _ := newAuthTestServer(t, testFixtureToken)

	noTokenResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/models/alice/my-model/branch/dev", "", strings.NewReader("{}"))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	noTokenResp.Body.Close()
	if noTokenResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token create-branch status = %d, want 401", noTokenResp.StatusCode)
	}

	correctResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/models/alice/my-model/branch/dev", "Bearer "+testFixtureToken, strings.NewReader("{}"))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	correctResp.Body.Close()
	if correctResp.StatusCode != http.StatusOK {
		t.Errorf("correct-token create-branch status = %d, want 200", correctResp.StatusCode)
	}
}

func TestAuth_Resolve_RequiresReadToken(t *testing.T) {
	ts, cas := newAuthTestServer(t, testFixtureToken)

	// Register the SHA-256 -> Xet hash mapping the CAS layer would normally
	// backfill once the paired shard upload completes, so the resolve below
	// has something to actually find rather than 404ing before auth even
	// matters.
	xetHash := merklehash.ComputeDataHash([]byte("model.bin content"))
	cas.sha256ToXet["abc123"] = xetHash
	cas.sizes[xetHash] = 500000

	// Create the repo and commit a file with the correct token first, so
	// there's something to resolve.
	createResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/repos/create", "Bearer "+testFixtureToken, strings.NewReader(`{"name":"my-model","organization":"alice","type":"model"}`))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	createResp.Body.Close()

	ndjson := `{"key":"lfsFile","value":{"path":"model.bin","algo":"sha256","oid":"abc123","size":500000}}` + "\n"
	commitResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/models/alice/my-model/commit/main", "Bearer "+testFixtureToken, strings.NewReader(ndjson))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	commitResp.Body.Close()

	noTokenResp, ok := doWithAuth(t, http.MethodHead, ts.URL+"/alice/my-model/resolve/main/model.bin", "", nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	noTokenResp.Body.Close()
	if noTokenResp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token resolve status = %d, want 401", noTokenResp.StatusCode)
	}

	correctResp, ok := doWithAuth(t, http.MethodHead, ts.URL+"/alice/my-model/resolve/main/model.bin", "Bearer "+testFixtureToken, nil)
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	correctResp.Body.Close()
	if correctResp.StatusCode != http.StatusOK {
		t.Errorf("correct-token resolve status = %d, want 200", correctResp.StatusCode)
	}
}

func TestAuth_AdversarialAuthorizationHeaders(t *testing.T) {
	ts, _ := newAuthTestServer(t, testFixtureToken)

	cases := []struct {
		name   string
		header string
	}{
		{"empty", ""},
		{"bearer no token", "Bearer"},
		{"bearer empty token", "Bearer "},
		{"wrong scheme", "NotBearer " + testFixtureToken},
		{"absurdly long token", "Bearer " + string(bytes.Repeat([]byte("x"), 100000))},
		{"binary garbage", "Bearer \x00\x01\x02"},
		{"embedded CRLF (header injection attempt)", "Bearer " + testFixtureToken + "\r\nX-Injected: true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, ok := doWithAuth(t, http.MethodGet, ts.URL+"/api/models/alice/my-model/xet-read-token/main", tc.header, nil)
			if !ok {
				// net/http's client refused to even send this header (a raw
				// control character or CRLF) - the malformed credential
				// never reached the server, which is just as good as the
				// server rejecting it itself.
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d for header %q, want 401 (none of these are the correct token)", resp.StatusCode, tc.header)
			}
		})
	}

	// Server must still be healthy after all that.
	healthResp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/repos/create", "Bearer "+testFixtureToken, strings.NewReader(`{"name":"health-check","type":"model"}`))
	if !ok {
		t.Fatal("request unexpectedly rejected client-side")
	}
	healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Errorf("server unhealthy after adversarial auth headers: repo-create status = %d", healthResp.StatusCode)
	}
}

// newRepoScopedTestServer is a Hub shim authenticating with
// SignedTokenAuth, the configuration cmd/xetd installs when -auth-token is
// set. Tokens are minted directly in these tests so each case can name the
// repo the credential is (and is not) allowed to touch.
func newRepoScopedTestServer(t *testing.T) (*httptest.Server, *auth.SignedTokenAuth) {
	t.Helper()
	cas := newFakeCAS()
	signed := auth.NewSignedTokenAuth(testFixtureToken)
	hubSrv := New("http://localhost:9999", cas)
	hubSrv.SetAuthenticator(signed)
	hubSrv.SetTokenMinter(signed)
	ts := httptest.NewServer(hubSrv)
	t.Cleanup(ts.Close)
	return ts, signed
}

// TestAuth_MintedTokenIsScopedToItsRepo is the regression test for the
// cross-repo hole reported by openxet: a read token minted for alice/sec
// read bob/private, and a write token minted for alice/sec created
// carol/x. Every repo-addressed route must reject the mismatch with 403,
// while the same token keeps working on its own repo.
func TestAuth_MintedTokenIsScopedToItsRepo(t *testing.T) {
	ts, signed := newRepoScopedTestServer(t)
	alice := auth.Repo{Type: "model", ID: "alice/sec"}
	readToken, _, err := signed.MintToken(auth.ScopeRead, "alice", alice, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	writeToken, _, err := signed.MintToken(auth.ScopeWrite, "alice", alice, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, method, path, token string
		body                      string
		want                      int
	}{
		{"read own repo info", http.MethodGet, "/api/models/alice/sec/revision/main", readToken, "", http.StatusOK},
		{"read other repo info", http.MethodGet, "/api/models/bob/private/revision/main", readToken, "", http.StatusForbidden},
		{"read own tree", http.MethodGet, "/api/models/alice/sec/tree/main", readToken, "", http.StatusOK},
		{"read other tree", http.MethodGet, "/api/models/bob/private/tree/main", readToken, "", http.StatusForbidden},
		{"resolve own repo", http.MethodHead, "/alice/sec/resolve/main/missing.bin", readToken, "", http.StatusNotFound},
		{"resolve other repo", http.MethodHead, "/bob/private/resolve/main/missing.bin", readToken, "", http.StatusForbidden},
		{"mint token for own repo", http.MethodGet, "/api/models/alice/sec/xet-read-token/main", readToken, "", http.StatusOK},
		{"mint token for other repo", http.MethodGet, "/api/models/bob/private/xet-read-token/main", readToken, "", http.StatusForbidden},
		{"commit own repo", http.MethodPost, "/api/models/alice/sec/commit/main", writeToken, `{"key":"header","value":{}}` + "\n", http.StatusOK},
		{"commit other repo", http.MethodPost, "/api/models/bob/private/commit/main", writeToken, `{"key":"header","value":{}}` + "\n", http.StatusForbidden},
		{"preupload other repo", http.MethodPost, "/api/models/bob/private/preupload/main", writeToken, `{"files":[]}`, http.StatusForbidden},
		{"branch other repo", http.MethodPost, "/api/models/bob/private/branch/dev", writeToken, "", http.StatusForbidden},
		{"lfs batch other repo", http.MethodPost, "/bob/private.git/info/lfs/objects/batch", writeToken, `{"operation":"upload","transfers":["xet"],"objects":[]}`, http.StatusForbidden},
		{"lfs batch own repo", http.MethodPost, "/alice/sec.git/info/lfs/objects/batch", writeToken, `{"operation":"upload","transfers":["xet"],"objects":[]}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, ok := doWithAuth(t, tc.method, ts.URL+tc.path, "Bearer "+tc.token, strings.NewReader(tc.body))
			if !ok {
				t.Fatal("request rejected client-side")
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, tc.want, body)
			}
		})
	}

	// Repo creation is namespace-scoped rather than exact-repo-scoped: a
	// token for alice/sec may create alice/new, but not carol/x.
	for _, tc := range []struct {
		name, body string
		want       int
	}{
		{"create inside namespace", `{"name":"new","organization":"alice","type":"model"}`, http.StatusOK},
		{"create outside namespace", `{"name":"x","organization":"carol","type":"model"}`, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/repos/create", "Bearer "+writeToken, strings.NewReader(tc.body))
			if !ok {
				t.Fatal("request rejected client-side")
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status = %d, want %d; body = %s", resp.StatusCode, tc.want, body)
			}
		})
	}

	// The shared secret remains the operator credential: it still reaches
	// every repo and namespace.
	resp, ok := doWithAuth(t, http.MethodPost, ts.URL+"/api/repos/create", "Bearer "+testFixtureToken, strings.NewReader(`{"name":"x","organization":"carol","type":"model"}`))
	if !ok {
		t.Fatal("request rejected client-side")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("shared secret create outside namespace: status = %d, want 200", resp.StatusCode)
	}
	resp, ok = doWithAuth(t, http.MethodGet, ts.URL+"/api/models/bob/private/revision/main", "Bearer "+testFixtureToken, nil)
	if !ok {
		t.Fatal("request rejected client-side")
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("shared secret other repo read: status = %d, want 200", resp.StatusCode)
	}
}
