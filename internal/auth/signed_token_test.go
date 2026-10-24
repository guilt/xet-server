package auth

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Every secret below is a hardcoded test fixture, not a real credential.
const signedFixtureSecret = "signed-fixture-secret-not-real"

var signedFixtureRepo = Repo{Type: "model", ID: "alice/sec"}

func reqWithHeader(value string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://example/", nil)
	if value != "" {
		r.Header.Set("Authorization", value)
	}
	return r
}

// basicCredential is the base64 half of a "Basic ..." header.
func basicCredential(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func TestSignedTokenAuth_SharedSecretBearerGrantsEverything(t *testing.T) {
	a := NewSignedTokenAuth(signedFixtureSecret)
	p, err := a.Authenticate(reqWithHeader("Bearer " + signedFixtureSecret))
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if !p.HasScope(ScopeRead) || !p.HasScope(ScopeWrite) {
		t.Error("shared secret should carry read and write")
	}
	if p.Subject() != SharedSecretSubject {
		t.Errorf("Subject() = %q, want %q", p.Subject(), SharedSecretSubject)
	}
}

func TestSignedTokenAuth_BasicWithSecretPasswordNamesTheUser(t *testing.T) {
	a := NewSignedTokenAuth(signedFixtureSecret)
	r := reqWithHeader("")
	r.SetBasicAuth("alice", signedFixtureSecret)
	p, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if p.Subject() != "alice" {
		t.Errorf("Subject() = %q, want alice", p.Subject())
	}
	if !p.HasScope(ScopeWrite) {
		t.Error("Basic with the shared secret should carry write")
	}

	r.SetBasicAuth("alice", "wrong-password")
	if _, err := a.Authenticate(r); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("wrong Basic password: err = %v, want ErrUnauthenticated", err)
	}
}

func TestSignedTokenAuth_MintedTokenRoundTrip(t *testing.T) {
	a := NewSignedTokenAuth(signedFixtureSecret)
	token, exp, err := a.MintToken(ScopeRead, "bob", signedFixtureRepo, time.Hour)
	if err != nil {
		t.Fatalf("MintToken() error = %v", err)
	}
	if until := time.Until(exp); until < 59*time.Minute || until > time.Hour {
		t.Errorf("exp %v is not about an hour away", exp)
	}
	p, err := a.Authenticate(reqWithHeader("Bearer " + token))
	if err != nil {
		t.Fatalf("Authenticate(minted) error = %v", err)
	}
	if p.Subject() != "bob" {
		t.Errorf("Subject() = %q, want bob", p.Subject())
	}
	if got := RepoOf(p); got != signedFixtureRepo {
		t.Errorf("RepoOf() = %v, want %v", got, signedFixtureRepo)
	}
	if !AllowsRepo(p, signedFixtureRepo) || AllowsRepo(p, Repo{Type: "model", ID: "bob/private"}) {
		t.Error("token must allow its own repo and no other")
	}
	if !p.HasScope(ScopeRead) || p.HasScope(ScopeWrite) {
		t.Error("read token must grant read only")
	}

	// The same token as a Basic password is also accepted.
	r := reqWithHeader("")
	r.SetBasicAuth("ignored", token)
	if _, err := a.Authenticate(r); err != nil {
		t.Errorf("minted token as Basic password: err = %v", err)
	}

	// A write token grants both.
	wtoken, _, _ := a.MintToken(ScopeWrite, "carol", signedFixtureRepo, time.Hour)
	wp, err := a.Authenticate(reqWithHeader("Bearer " + wtoken))
	if err != nil {
		t.Fatalf("Authenticate(write token) error = %v", err)
	}
	if !wp.HasScope(ScopeRead) || !wp.HasScope(ScopeWrite) {
		t.Error("write token must grant read and write")
	}
}

func TestSignedTokenAuth_RejectsTamperedExpiredAndForeignTokens(t *testing.T) {
	a := NewSignedTokenAuth(signedFixtureSecret)
	token, _, _ := a.MintToken(ScopeRead, "bob", signedFixtureRepo, time.Hour)

	// Flip the scope in the payload: MAC no longer matches.
	parts := strings.Split(token, ".")
	parts[2] = string(ScopeWrite)
	tampered := strings.Join(parts, ".")
	if _, err := a.Authenticate(reqWithHeader("Bearer " + tampered)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("tampered scope: err = %v, want ErrUnauthenticated", err)
	}

	// Swap in a different repo: MAC no longer matches, which is what
	// stops a token for one repo from being rewritten for another.
	parts = strings.Split(token, ".")
	parts[5] = hex.EncodeToString([]byte("bob/private"))
	if _, err := a.Authenticate(reqWithHeader("Bearer " + strings.Join(parts, "."))); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("tampered repo: err = %v, want ErrUnauthenticated", err)
	}

	// Minted under a different secret.
	other := NewSignedTokenAuth("a-different-fixture-secret")
	foreign, _, _ := other.MintToken(ScopeWrite, "bob", signedFixtureRepo, time.Hour)
	if _, err := a.Authenticate(reqWithHeader("Bearer " + foreign)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("foreign token: err = %v, want ErrUnauthenticated", err)
	}

	// Expired: mint with a 1s ttl and back-date by rebuilding the MAC.
	expired := mintedPayload(time.Now().Add(-time.Minute).Unix(), ScopeRead, "bob", signedFixtureRepo)
	expired += "." + hexMAC(a, expired)
	if _, err := a.Authenticate(reqWithHeader("Bearer " + expired)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("expired token: err = %v, want ErrUnauthenticated", err)
	}

	// Garbage shapes.
	for _, bad := range []string{"", "Bearer ", "Bearer xst1.a.b", "Bearer xst1.1.2.3.4.5", "Basic not-base64"} {
		if _, err := a.Authenticate(reqWithHeader(bad)); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("header %q: err = %v, want ErrUnauthenticated", bad, err)
		}
	}
}

// TestSignedTokenAuth_AdminScopeIsTheSecretOnly: the raw secret (Bearer
// or Basic password) holds every scope including admin; a minted token
// never does, and one forged to claim it is refused outright.
func TestSignedTokenAuth_AdminScopeIsTheSecretOnly(t *testing.T) {
	a := NewSignedTokenAuth(signedFixtureSecret)
	for _, header := range []string{"Bearer " + signedFixtureSecret, "Basic " + basicCredential("operator", signedFixtureSecret)} {
		p, err := a.Authenticate(reqWithHeader(header))
		if err != nil {
			t.Fatalf("%s: %v", header, err)
		}
		for _, scope := range []Scope{ScopeRead, ScopeWrite, ScopeAdmin} {
			if !p.HasScope(scope) {
				t.Errorf("secret via %q lacks %s", header[:6], scope)
			}
		}
	}
	minted, _, err := a.MintToken(ScopeWrite, "alice", signedFixtureRepo, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Authenticate(reqWithHeader("Bearer " + minted))
	if err != nil {
		t.Fatal(err)
	}
	if p.HasScope(ScopeAdmin) || !p.HasScope(ScopeWrite) {
		t.Errorf("minted write token: admin = %v, write = %v", p.HasScope(ScopeAdmin), p.HasScope(ScopeWrite))
	}
	forged := mintedPayload(time.Now().Add(time.Hour).Unix(), ScopeAdmin, "alice", signedFixtureRepo)
	forged += "." + hexMAC(a, forged)
	if _, err := a.Authenticate(reqWithHeader("Bearer " + forged)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("token claiming admin scope: err = %v, want ErrUnauthenticated", err)
	}
}

func TestSignedTokenAuth_MintRefusesBadInputs(t *testing.T) {
	a := NewSignedTokenAuth(signedFixtureSecret)
	if _, _, err := a.MintToken(Scope("admin"), "x", signedFixtureRepo, time.Hour); err == nil {
		t.Error("minting an unknown scope should fail")
	}
	if _, _, err := a.MintToken(ScopeRead, "x", signedFixtureRepo, 0); err == nil {
		t.Error("minting with a zero ttl should fail")
	}
	if _, _, err := NewSignedTokenAuth("").MintToken(ScopeRead, "x", signedFixtureRepo, time.Hour); err == nil {
		t.Error("minting with an empty secret should fail")
	}
}

// TestSignedTokenAuth_RepoScopedCreateOnlyInsideNamespace pins the repo
// creation rule: a write token minted for alice/sec may add another repo
// under alice, but not one under bob; only the shared secret's admin scope
// crosses namespaces.
func TestSignedTokenAuth_RepoScopedCreateOnlyInsideNamespace(t *testing.T) {
	a := NewSignedTokenAuth(signedFixtureSecret)
	token, _, err := a.MintToken(ScopeWrite, "alice", signedFixtureRepo, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Authenticate(reqWithHeader("Bearer " + token))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		repo Repo
		want bool
	}{
		{Repo{Type: "model", ID: "alice/new"}, true},
		{Repo{Type: "dataset", ID: "alice/data"}, true},
		{Repo{Type: "model", ID: "bob/x"}, false},
		{Repo{Type: "model", ID: "carol/x"}, false},
	} {
		if got := AllowsRepoCreate(p, tc.repo); got != tc.want {
			t.Errorf("AllowsRepoCreate(%v) = %v, want %v", tc.repo, got, tc.want)
		}
	}

	admin, err := a.Authenticate(reqWithHeader("Bearer " + signedFixtureSecret))
	if err != nil {
		t.Fatal(err)
	}
	if !AllowsRepoCreate(admin, Repo{Type: "model", ID: "bob/private"}) {
		t.Error("shared secret must be able to create repositories in any namespace")
	}
}

// TestSignedTokenAuth_OldUnscopedTokenFormatRejected: tokens from the
// previous format carried no repo, so accepting them would reopen the
// cross-repo hole. They are refused rather than downgraded.
func TestSignedTokenAuth_OldUnscopedTokenFormatRejected(t *testing.T) {
	a := NewSignedTokenAuth(signedFixtureSecret)
	old := "xst1." + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10) + ".read." + hex.EncodeToString([]byte("bob"))
	old += "." + hexMAC(a, old)
	if _, err := a.Authenticate(reqWithHeader("Bearer " + old)); !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("xst1 token: err = %v, want ErrUnauthenticated", err)
	}
}

func hexMAC(a *SignedTokenAuth, payload string) string {
	const hexdigits = "0123456789abcdef"
	mac := a.mac(payload)
	out := make([]byte, 0, len(mac)*2)
	for _, b := range mac {
		out = append(out, hexdigits[b>>4], hexdigits[b&0x0f])
	}
	return string(out)
}
