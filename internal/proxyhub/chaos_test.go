package proxyhub

// Chaos/reliability tests for a MISBEHAVING UPSTREAM - the real Hub (or
// whatever -upstream-hub-url points at) hanging before it ever sends
// response headers, dying only after the first call has already been
// cached, returning a real HTTP 200 carrying garbage/truncated JSON, or
// stalling halfway through a paginated tree listing. The invariant under
// test throughout is the one this package exists for (see the package
// doc comment): ANY upstream failure falls back to whatever Embedded
// already holds, no matter how old, and a request never fails outright
// once a fallback value exists - while a genuinely cold cache still
// fails CLEANLY (a 502 with a JSON body) and FAST, never hanging or
// panicking.
//
// Deliberately NOT re-covered here: the slow-drip case (headers sent
// immediately, body stalled) and callContext's own zero-value escape
// hatch, both already covered in timeout_test.go; and casserver's own
// upload/eviction chaos, covered in internal/casserver/chaos_test.go.
//
// Every test uses a short MetadataCallTimeout and/or a short
// client-side context deadline so the whole file stays well under a
// couple of seconds and is deterministic under `go test -race`.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guilt/xet-server/internal/hfclient"
	"github.com/guilt/xet-server/internal/merklehash"
)

const testCASBaseURL = "http://localhost:8420"

// newHangingHubURL returns the base URL of a listener that completes the
// TCP handshake and then never writes a response - a completely
// unresponsive upstream (a hung huggingface.co, a network partition that
// drops responses but not the handshake). This is proxyhub's own copy of
// internal/hfclient/timeout_test.go's newHangingServer, adapted to hand
// back a base URL a *Server can be pointed at; closing the connection
// outright would be a materially different (and much easier) failure for
// an HTTP client to notice - an immediate reset, not a hang.
func newHangingHubURL(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				<-done
				conn.Close()
			}()
		}
	}()
	t.Cleanup(func() {
		close(done)
		ln.Close()
	})
	return "http://" + ln.Addr().String()
}

// newTestServerAt is newTestServer's (proxyhub_test.go) counterpart for
// an upstream that has no *httptest.Server to hand over - the raw
// hanging listeners above.
func newTestServerAt(hubBaseURL string) *Server {
	return New(hubBaseURL, testCASBaseURL)
}

// hangAfterFirstCall serves healthy for the first request and then hangs
// on every subsequent one until that request's own context is canceled -
// i.e. until proxyhub's MetadataCallTimeout (or the downstream client)
// gives up. Models the common real-world shape of upstream trouble:
// something got cached while the Hub was fine, and the Hub then stopped
// answering.
func hangAfterFirstCall(healthy http.HandlerFunc) http.HandlerFunc {
	var calls atomic.Int64
	return func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			healthy(w, r)
			return
		}
		<-r.Context().Done()
	}
}

func repoInfoHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(hfclient.RepoInfo{ID: "alice/my-model", SHA: "main"})
}

func xetTokenHandler(w http.ResponseWriter, r *http.Request) {
	// Exp must stay comfortably in the future: since the stale-fallback guard
	// (token.go's tokenSafetyMargin) refuses to serve an expired cached token,
	// a stale-token test only exercises the offline path if the cached token
	// is still usable when it's served.
	json.NewEncoder(w).Encode(hfclient.XetToken{CasURL: "https://real-cas.example.invalid", Exp: time.Now().Add(time.Hour).Unix(), AccessToken: "real-upstream-token"})
}

func resolveHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Xet-Hash", testXetHashHex)
	w.Header().Set("X-Linked-Size", "42")
	w.Header().Set("ETag", `"etag123"`)
	w.WriteHeader(http.StatusOK)
}

const testXetHashHex = "abababababababababababababababababababababababababababababababab"

// wantJSONError asserts resp carries this package's standard
// httpErrorJSON body shape - proving the failure was handled
// deliberately (through writeUpstreamError) rather than by a panic
// unwinding through the handler, which the client would see as a bare
// EOF/500 with no body at all.
func wantJSONError(t *testing.T, resp *http.Response) {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v (want writeUpstreamError's JSON shape)", err)
	}
	if body["error"] == "" {
		t.Errorf("error body = %+v, want a non-empty \"error\" field", body)
	}
}

// TestChaos_RepoInfoHungUpstreamFallsBackToCachedRevision proves the
// fully-hung-before-headers case (distinct from timeout_test.go's
// slow-drip, where headers DO arrive) still reaches the stale-fallback
// path, and reaches it within MetadataCallTimeout rather than waiting on
// hfclient's much longer Transport-level ResponseHeaderTimeout.
func TestChaos_RepoInfoHungUpstreamFallsBackToCachedRevision(t *testing.T) {
	s := newTestServerAt(newHangingHubURL(t))
	s.MetadataCallTimeout = 100 * time.Millisecond
	s.Embedded.IngestRepoInfo("model", "alice/my-model", "main") // as if a previous healthy fetch had ingested it

	ts := httptest.NewServer(s)
	defer ts.Close()

	start := time.Now()
	resp, err := http.Get(ts.URL + "/api/models/alice/my-model/revision/main")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (must fall back to the already-ingested revision)", resp.StatusCode)
	}
	if elapsed > 2*time.Second {
		t.Errorf("request took %v, want well under 2s (MetadataCallTimeout must cut the hung upstream call short)", elapsed)
	}
}

// TestChaos_HungUpstreamWithNothingCachedFailsCleanlyAndFast proves the
// other half of the same scenario: with no cached value to fall back to,
// each read endpoint must produce a real 502 with a JSON body promptly -
// not hang for the downstream client's full patience, and not panic.
func TestChaos_HungUpstreamWithNothingCachedFailsCleanlyAndFast(t *testing.T) {
	s := newTestServerAt(newHangingHubURL(t))
	s.MetadataCallTimeout = 100 * time.Millisecond

	ts := httptest.NewServer(s)
	defer ts.Close()

	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"repo-info", http.MethodGet, "/api/models/alice/my-model/revision/main"},
		{"xet-read-token", http.MethodGet, "/api/models/alice/my-model/xet-read-token/main"},
		{"resolve", http.MethodHead, "/alice/my-model/resolve/main/model.bin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, ts.URL+tc.path, nil)
			start := time.Now()
			resp, err := http.DefaultClient.Do(req)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("%s error = %v (want a clean HTTP response, not a transport failure)", tc.method, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Errorf("status = %d, want 502 with nothing cached to fall back to", resp.StatusCode)
			}
			if elapsed > 2*time.Second {
				t.Errorf("request took %v to fail, want well under 2s", elapsed)
			}
			if tc.method != http.MethodHead { // a HEAD response carries no body to inspect
				wantJSONError(t, resp)
			}
		})
	}
}

// TestChaos_UpstreamDiesAfterFirstCallThenEveryRepeatStillSucceeds is
// the "cached once, upstream then broken forever" scenario: with the
// default CacheTTL of -1 every request re-attempts upstream, so each
// repeat pays MetadataCallTimeout and then falls back - the point being
// that no repeat ever FAILS, however many times in a row upstream hangs,
// and the served body stays correct rather than degrading to an empty
// 200. Also the "survived chaos, still serving" proof (cf.
// TestRepoInfo_OfflineAfterCacheStillServesRegardlessOfTTL).
func TestChaos_UpstreamDiesAfterFirstCallThenEveryRepeatStillSucceeds(t *testing.T) {
	hubTS := httptest.NewServer(hangAfterFirstCall(repoInfoHandler))
	defer hubTS.Close()

	s := newTestServer(hubTS, testCASBaseURL)
	s.MetadataCallTimeout = 100 * time.Millisecond
	ts := httptest.NewServer(s)
	defer ts.Close()

	url := ts.URL + "/api/models/alice/my-model/revision/main"

	primeResp, err := http.Get(url)
	if err != nil {
		t.Fatalf("priming GET error = %v", err)
	}
	primeResp.Body.Close()
	if primeResp.StatusCode != http.StatusOK {
		t.Fatalf("priming status = %d, want 200", primeResp.StatusCode)
	}

	// Upstream is now permanently hung. Every one of these must still be
	// served from Embedded, with the right content.
	start := time.Now()
	const repeats = 5
	for i := 0; i < repeats; i++ {
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET #%d error = %v", i, err)
		}
		var info hfclient.RepoInfo
		decodeErr := json.NewDecoder(resp.Body).Decode(&info)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET #%d status = %d, want 200 (a fallback value exists; no repeat may fail outright)", i, resp.StatusCode)
		}
		if decodeErr != nil {
			t.Fatalf("GET #%d decode error = %v", i, decodeErr)
		}
		if info.ID != "alice/my-model" || info.SHA != "main" {
			t.Errorf("GET #%d body = %+v, want the cached revision served correctly", i, info)
		}
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("%d fallback requests took %v, want well under 2s (each bounded by MetadataCallTimeout)", repeats, elapsed)
	}
}

// TestChaos_XetTokenUpstreamHangsAfterFirstCallStillServesStaleToken
// covers the one endpoint that cannot fall back through Embedded at all
// (see token.go): its stale fallback comes from xetTokenCache via
// fetchTokenCache, and must survive the same hung upstream - including
// still rewriting CasURL and passing the real AccessToken through.
func TestChaos_XetTokenUpstreamHangsAfterFirstCallStillServesStaleToken(t *testing.T) {
	hubTS := httptest.NewServer(hangAfterFirstCall(xetTokenHandler))
	defer hubTS.Close()

	s := newTestServer(hubTS, testCASBaseURL)
	s.MetadataCallTimeout = 100 * time.Millisecond
	ts := httptest.NewServer(s)
	defer ts.Close()

	url := ts.URL + "/api/models/alice/my-model/xet-read-token/main"
	primeResp, err := http.Get(url)
	if err != nil {
		t.Fatalf("priming GET error = %v", err)
	}
	primeResp.Body.Close()

	start := time.Now()
	resp, err := http.Get(url)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (stale token still servable with upstream hung)", resp.StatusCode)
	}
	var tok hfclient.XetToken
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		t.Fatalf("decode token error = %v", err)
	}
	if tok.CasURL != testCASBaseURL {
		t.Errorf("CasURL = %q, want it still rewritten to this proxy on the stale path", tok.CasURL)
	}
	if tok.AccessToken != "real-upstream-token" {
		t.Errorf("AccessToken = %q, want the real upstream token passed through unchanged", tok.AccessToken)
	}
	if elapsed > 2*time.Second {
		t.Errorf("request took %v, want well under 2s", elapsed)
	}
}

// TestChaos_ResolveUpstreamHangsAfterFirstCallStillServesCachedMetadata
// exercises the resolve read path's fallback under a hung upstream - the
// path whose local answer additionally depends on this package's own
// CAS-bridge FileSize lookup (see Server.FileSize) surviving alongside
// Embedded's file record.
func TestChaos_ResolveUpstreamHangsAfterFirstCallStillServesCachedMetadata(t *testing.T) {
	hubTS := httptest.NewServer(hangAfterFirstCall(resolveHandler))
	defer hubTS.Close()

	s := newTestServer(hubTS, testCASBaseURL)
	s.MetadataCallTimeout = 100 * time.Millisecond
	ts := httptest.NewServer(s)
	defer ts.Close()

	primeReq, _ := http.NewRequest(http.MethodHead, ts.URL+"/alice/my-model/resolve/main/model.bin", nil)
	primeResp, err := http.DefaultClient.Do(primeReq)
	if err != nil {
		t.Fatalf("priming HEAD error = %v", err)
	}
	primeResp.Body.Close()
	if primeResp.StatusCode != http.StatusOK {
		t.Fatalf("priming status = %d, want 200", primeResp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodHead, ts.URL+"/alice/my-model/resolve/main/model.bin", nil)
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("HEAD error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (cached resolve metadata still servable with upstream hung)", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Xet-Hash"); got != testXetHashHex {
		t.Errorf("X-Xet-Hash = %q, want the cached hash %q", got, testXetHashHex)
	}
	if got := resp.Header.Get("X-Linked-Size"); got != "42" {
		t.Errorf("X-Linked-Size = %q, want 42 (from this package's own recorded FileSize)", got)
	}
	if elapsed > 2*time.Second {
		t.Errorf("request took %v, want well under 2s", elapsed)
	}
}

// garbageJSONHandler answers with a real HTTP 200 whose body is not JSON
// at all - an upstream that is reachable and "healthy" at the HTTP layer
// but whose payload cannot be parsed (a captive portal, a misrouted CDN
// error page served as 200, a partially-deployed API).
func garbageJSONHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<html>this is definitely not the JSON you asked for</html>"))
}

// truncatedJSONHandler promises more bytes than it writes, so the
// connection dies mid-body and the decoder sees an unexpected EOF - the
// same class of failure as garbage, reached differently.
func truncatedJSONHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", "200")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"id":"alice/my-mod`))
}

// TestChaos_MalformedUpstreamJSONWithNothingCachedIsACleanBadGateway
// pins down that an hfclient JSON decode failure - which surfaces as a
// plain fmt.Errorf("decode ...: %w") value, NOT a *hfclient.StatusError
// (see hfclient.RepoInfo/ListTree/GetXetToken) - travels the exact same
// writeUpstreamError path as a network failure, yielding a 502 with a
// JSON body rather than a panic, an empty 200, or the upstream's own
// misleading 200 relayed onward.
func TestChaos_MalformedUpstreamJSONWithNothingCachedIsACleanBadGateway(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		path    string
	}{
		{"repo-info/garbage", garbageJSONHandler, "/api/models/alice/my-model/revision/main"},
		{"repo-info/truncated", truncatedJSONHandler, "/api/models/alice/my-model/revision/main"},
		{"tree/garbage", garbageJSONHandler, "/api/models/alice/my-model/tree/main"},
		{"tree/truncated", truncatedJSONHandler, "/api/models/alice/my-model/tree/main"},
		{"xet-read-token/garbage", garbageJSONHandler, "/api/models/alice/my-model/xet-read-token/main"},
		{"xet-read-token/truncated", truncatedJSONHandler, "/api/models/alice/my-model/xet-read-token/main"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hubTS := httptest.NewServer(tc.handler)
			defer hubTS.Close()

			s := newTestServer(hubTS, testCASBaseURL)
			s.MetadataCallTimeout = 500 * time.Millisecond
			ts := httptest.NewServer(s)
			defer ts.Close()

			resp, err := http.Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("GET error = %v (want a clean HTTP response)", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status = %d, want 502 (an undecodable upstream body is an upstream failure like any other)", resp.StatusCode)
			}
			wantJSONError(t, resp)
		})
	}
}

// TestChaos_MalformedUpstreamJSONFallsBackToCache is the same malformed
// -body failure with a cached value present: it must be indistinguishable
// from a network failure, i.e. serve the stale value rather than
// surfacing a decode error to the caller.
func TestChaos_MalformedUpstreamJSONFallsBackToCache(t *testing.T) {
	hubTS := httptest.NewServer(http.HandlerFunc(garbageJSONHandler))
	defer hubTS.Close()

	s := newTestServer(hubTS, testCASBaseURL)
	s.MetadataCallTimeout = 500 * time.Millisecond
	s.Embedded.IngestRepoInfo("model", "alice/my-model", "main")
	// The tree read path falls back through the very same revision
	// record, so one ingest covers both assertions below.
	s.Embedded.IngestFile("model", "alice/my-model", "main", "README.md", "aaa", 10, merklehash.Hash{})

	ts := httptest.NewServer(s)
	defer ts.Close()

	for _, path := range []string{
		"/api/models/alice/my-model/revision/main",
		"/api/models/alice/my-model/tree/main",
	} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s error = %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200 (malformed upstream JSON must fall back to cache like any other failure)", path, resp.StatusCode)
		}
	}
}

// TestChaos_ListTreeHungSecondPageHasNoPerPageBound documents a
// DELIBERATE, documented gap rather than a defect: ListTree paginates
// internally within a single context (see hfclient's own doc comment on
// defaultHTTPClient and proxyhub's package doc comment), so
// MetadataCallTimeout is intentionally NOT applied to it - a fixed
// per-call bound would abort a legitimately large but healthy listing
// partway through. Consequence: if page 2 hangs, nothing in this package
// cuts the request short; the only backstop is hfclient's
// Transport-level ResponseHeaderTimeout (10s in production). This test
// therefore supplies its OWN patience bound via a client-side context
// and asserts the request blew well past MetadataCallTimeout without
// being bounded by it. See TestChaos_ListTreeSlowSecondPageStill
// CompletesForAPatientClient for the upside this buys.
func TestChaos_ListTreeHungSecondPageHasNoPerPageBound(t *testing.T) {
	hangURL := newHangingHubURL(t)
	hubTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "<"+hangURL+"/api/models/alice/my-model/tree/main?cursor=page2>; rel=\"next\"")
		json.NewEncoder(w).Encode([]hfclient.TreeEntry{{Type: "file", Path: "README.md", Size: 10, OID: "aaa"}})
	}))
	defer hubTS.Close()

	s := newTestServer(hubTS, testCASBaseURL)
	s.MetadataCallTimeout = 50 * time.Millisecond // deliberately ignored by handleListTree
	ts := httptest.NewServer(s)
	defer ts.Close()

	const patience = 400 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), patience)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/models/alice/my-model/tree/main", nil)

	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	elapsed := time.Since(start)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("tree listing completed in %v despite a hung second page - a per-page bound now exists; this test (and the doc comments claiming ListTree is unbounded) need revisiting", elapsed)
	}
	if elapsed < 2*s.MetadataCallTimeout {
		t.Errorf("request ended after %v, want it to run past MetadataCallTimeout (%v) - that bound is deliberately not applied to ListTree", elapsed, s.MetadataCallTimeout)
	}
	if elapsed > 2*time.Second {
		t.Errorf("request took %v, want it bounded by this test's own %v deadline", elapsed, patience)
	}
}

// TestChaos_ListTreeSlowSecondPageStillCompletesForAPatientClient is the
// flip side of the gap above: a slow-but-healthy second page must still
// be followed to completion, with every entry ingested - exactly what a
// per-call bound on ListTree would have broken.
func TestChaos_ListTreeSlowSecondPageStillCompletesForAPatientClient(t *testing.T) {
	page2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond) // slow, but genuinely healthy
		json.NewEncoder(w).Encode([]hfclient.TreeEntry{{Type: "file", Path: "data/train.bin", Size: 20, OID: "bbb"}})
	}))
	defer page2.Close()

	hubTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "<"+page2.URL+"/api/models/alice/my-model/tree/main?cursor=page2>; rel=\"next\"")
		json.NewEncoder(w).Encode([]hfclient.TreeEntry{{Type: "file", Path: "README.md", Size: 10, OID: "aaa"}})
	}))
	defer hubTS.Close()

	s := newTestServer(hubTS, testCASBaseURL)
	s.MetadataCallTimeout = 50 * time.Millisecond // far shorter than the page-2 delay, and deliberately not applied here
	ts := httptest.NewServer(s)
	defer ts.Close()

	start := time.Now()
	resp, err := http.Get(ts.URL + "/api/models/alice/my-model/tree/main")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a slow-but-healthy paginated listing must complete)", resp.StatusCode)
	}
	var entries []hfclient.TreeEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		t.Fatalf("decode entries error = %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("got %d entries, want both pages' entries", len(entries))
	}
	if !s.Embedded.HasFile("model", "alice/my-model", "main", "data/train.bin") {
		t.Error("second page's file was not ingested - pagination was cut short")
	}
	if elapsed > 2*time.Second {
		t.Errorf("request took %v, want a little over the 300ms page-2 delay", elapsed)
	}
}

// TestChaos_ConcurrentColdCacheRequestsWhileUpstreamIsSlow is the
// thundering-herd case: many callers arrive for the same cold keys at
// once while upstream is slow, so every one of them misses, calls
// upstream, and races to ingest the same repo/revision/file records (and
// this package's own fileSizeByXetHash map). There is deliberately no
// single-flight coalescing here, so what matters is that the concurrent
// ingests are safe and every caller still gets a correct answer - run
// under `go test -race` this is the file's data-race check.
func TestChaos_ConcurrentColdCacheRequestsWhileUpstreamIsSlow(t *testing.T) {
	const upstreamDelay = 150 * time.Millisecond
	hubTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(upstreamDelay)
		switch {
		case strings.Contains(r.URL.Path, "/revision/"):
			repoInfoHandler(w, r)
		case strings.Contains(r.URL.Path, "/tree/"):
			json.NewEncoder(w).Encode([]hfclient.TreeEntry{
				{Type: "file", Path: "README.md", Size: 10, OID: "aaa"},
				{Type: "file", Path: "data/train.bin", Size: 20, OID: "bbb", XetHash: testXetHashHex},
			})
		case strings.Contains(r.URL.Path, "/xet-read-token/"):
			xetTokenHandler(w, r)
		case strings.Contains(r.URL.Path, "/resolve/"):
			resolveHandler(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer hubTS.Close()

	s := newTestServer(hubTS, testCASBaseURL)
	ts := httptest.NewServer(s)
	defer ts.Close()

	requests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/models/alice/my-model/revision/main"},
		{http.MethodGet, "/api/models/alice/my-model/tree/main"},
		{http.MethodGet, "/api/models/alice/my-model/xet-read-token/main"},
		{http.MethodHead, "/alice/my-model/resolve/main/model.bin"},
	}

	const perRequest = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string

	start := time.Now()
	for _, rq := range requests {
		for i := 0; i < perRequest; i++ {
			wg.Add(1)
			go func(method, path string, i int) {
				defer wg.Done()
				req, _ := http.NewRequest(method, ts.URL+path, nil)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("%s %s #%d: %v", method, path, i, err))
					mu.Unlock()
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					mu.Lock()
					failures = append(failures, fmt.Sprintf("%s %s #%d: status %d", method, path, i, resp.StatusCode))
					mu.Unlock()
				}
			}(rq.method, rq.path, i)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)

	if len(failures) > 0 {
		t.Errorf("%d of %d concurrent cold-cache requests failed against a slow upstream:\n%s",
			len(failures), len(requests)*perRequest, strings.Join(failures, "\n"))
	}
	if elapsed > 2*time.Second {
		t.Errorf("herd took %v, want the concurrent requests to overlap (upstream delay is %v each)", elapsed, upstreamDelay)
	}
}
