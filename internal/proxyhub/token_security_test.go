package proxyhub

// Regression tests for the openxet security report (2026-10-23):
// caches whose values depend on authorization must be keyed by the
// caller's credential, and an upstream 401/403 must never be hidden
// behind another caller's cached token or private-repo metadata.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/guilt/xet-server/internal/hfclient"
)

const (
	aliceCredential = "Bearer alice-test-fixture-token"
	wrongCredential = "Bearer wrong-test-fixture-token"
	aliceTokenValue = "alice-upstream-xet-token"
)

func TestXetTokenCache_IsPerCallerCredential(t *testing.T) {
	fetches := 0
	hubTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches++
		if r.Header.Get("Authorization") != aliceCredential {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(hfclient.XetToken{
			CasURL:      "https://real-cas.example.invalid",
			AccessToken: aliceTokenValue,
			Exp:         time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer hubTS.Close()

	s := newTestServer(hubTS, "http://localhost:8420")
	s.CacheTTL = time.Hour
	ts := httptest.NewServer(s)
	defer ts.Close()

	get := func(authHeader string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/models/alice/private/xet-read-token/main", nil)
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET error = %v", err)
		}
		return resp
	}

	alice := get(aliceCredential)
	if alice.StatusCode != http.StatusOK {
		t.Fatalf("alice status = %d, want 200", alice.StatusCode)
	}
	var tok hfclient.XetToken
	if err := json.NewDecoder(alice.Body).Decode(&tok); err != nil {
		t.Fatalf("decode alice token: %v", err)
	}
	alice.Body.Close()
	if tok.AccessToken != aliceTokenValue {
		t.Fatalf("alice AccessToken = %q, want %q", tok.AccessToken, aliceTokenValue)
	}
	if fetches != 1 {
		t.Fatalf("upstream fetches after alice = %d, want 1", fetches)
	}

	for name, header := range map[string]string{"anonymous": "", "wrong-token": wrongCredential} {
		resp := get(header)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want 401 (must not receive alice's cached token)", name, resp.StatusCode)
		}
		if string(body) == aliceTokenValue {
			t.Errorf("%s response leaked alice's upstream token", name)
		}
	}

	// Alice still gets her own cached value, and the failed callers did
	// not poison or evict it.
	aliceAgain := get(aliceCredential)
	if aliceAgain.StatusCode != http.StatusOK {
		t.Fatalf("alice second status = %d, want 200", aliceAgain.StatusCode)
	}
	var tok2 hfclient.XetToken
	if err := json.NewDecoder(aliceAgain.Body).Decode(&tok2); err != nil {
		t.Fatalf("decode alice second token: %v", err)
	}
	aliceAgain.Body.Close()
	if tok2.AccessToken != aliceTokenValue {
		t.Errorf("alice second AccessToken = %q, want %q", tok2.AccessToken, aliceTokenValue)
	}
	// Alice's second request must be a cache hit: only the two failed
	// callers above should have added upstream calls.
	if fetches != 3 {
		t.Errorf("upstream fetches after alice's cached second request = %d, want 3", fetches)
	}
}

func TestRepoInfoCache_DoesNotServeAnotherCallersPrivateMetadata(t *testing.T) {
	hubTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != aliceCredential {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(hfclient.RepoInfo{ID: "alice/private", SHA: "main"})
	}))
	defer hubTS.Close()

	s := newTestServer(hubTS, "http://localhost:8420")
	ts := httptest.NewServer(s)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/models/alice/private/revision/main", nil)
	req.Header.Set("Authorization", aliceCredential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("alice GET error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("alice status = %d, want 200", resp.StatusCode)
	}
	if !s.Embedded.HasRevision("model", "alice/private", "main") {
		t.Fatal("alice's repo info was not cached in Embedded")
	}

	for name, header := range map[string]string{"anonymous": "", "wrong-token": wrongCredential} {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/models/alice/private/revision/main", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s GET error = %v", name, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s status = %d, want 401 (must not serve alice's cached private metadata)", name, resp.StatusCode)
		}
	}
}

// TestXetToken_NotWrittenToSnapshot pins the other half of the token
// guarantee: the proxy may cache an upstream xet access token in memory
// (for the CAS 401 heal and the same-caller stale fallback), but it must
// never persist the value - or the caller credential - into a data-dir
// snapshot that later becomes a plain xetd data directory.
func TestXetToken_NotWrittenToSnapshot(t *testing.T) {
	const tokenValue = "snapshot-must-not-contain-this-token"
	hubTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(hfclient.XetToken{
			CasURL:      "https://real-cas.example.invalid",
			AccessToken: tokenValue,
			Exp:         time.Now().Add(time.Hour).Unix(),
		})
	}))
	defer hubTS.Close()

	s := newTestServer(hubTS, "http://localhost:8420")
	ts := httptest.NewServer(s)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/models/alice/my-model/xet-read-token/main", nil)
	req.Header.Set("Authorization", aliceCredential)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	dir := t.TempDir()
	snapshotPath := filepath.Join(dir, "hubserver-snapshot.json")
	if err := s.Embedded.Snapshot(snapshotPath); err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	for _, secret := range []string{tokenValue, aliceCredential} {
		if bytes.Contains(data, []byte(secret)) {
			t.Errorf("snapshot contains %q; tokens and caller credentials must stay in memory", secret)
		}
	}
}
