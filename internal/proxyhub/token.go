package proxyhub

// token.go: GET /api/{repo_type}s/{repo_id}/xet-{read,write}-token/{revision}.
// The one read endpoint that CANNOT delegate to Embedded - hubserver's
// own xet-token handler mints a fake random token, worthless against
// the real upstream CAS - so this package caches the real XetToken
// value itself, independent of Embedded, under a token-specific freshness
// policy: cache entries are keyed by the caller credential and an upstream
// 401/403 is never hidden by a stale entry (see fetchTokenCache). See the
// package doc
// comment for why CasURL is rewritten while AccessToken passes through
// unchanged, and why the real upstream CAS URL is ALSO tracked
// separately in casURLCache regardless of this endpoint's own per-repo
// cache entry (cmd/xet-proxyd's CAS-facing routing needs one shared
// "most recently known" value - see UpstreamCASBaseURL).

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/hfclient"
)

// tokenSafetyMargin is how far in the future a cached xet token's exp must
// still be for it to be served from cache (fetchTokenCache below). A token
// any closer to expiry than this - or already past it - is
// worthless: the first CAS request presenting it would be rejected with a 401
// the client can't explain. This mirrors huggingface_hub's own 60s
// XET_CONNECTION_INFO_SAFETY_PERIOD; xet-core's docs recommend at least 30s.
const tokenSafetyMargin = 60 * time.Second

func (s *Server) handleXetToken(w http.ResponseWriter, r *http.Request, repoType, repoID, revision string, kind hfclient.XetTokenKind) {
	cred := auth.CredentialFromRequest(r)
	// The caller's credential MUST be part of the key: two callers asking
	// for the same repo/ref/kind get different upstream principals, and
	// upstream tokens are bearer credentials for exactly one principal.
	// Keying only by repo/ref/kind let any caller (including anonymous or
	// wrong-token ones) receive a token another user had cached; see
	// credentialFingerprint.
	key := cacheKey(repoType, repoID, revision, strconv.Itoa(int(kind)), credentialFingerprint(r))

	tok, err := fetchTokenCache(s.NoCache, s.xetTokenCache, s.CacheTTL, key,
		func() (*hfclient.XetToken, error) {
			callCtx, cancel := s.callContext(r)
			defer cancel()
			return s.Hub.GetXetToken(callCtx, cred, repoType, repoID, revision, kind)
		},
	)
	if err != nil {
		writeUpstreamError(w, err)
		return
	}

	if tok.CasURL != "" {
		// Recorded regardless of NoCache: this is routing state (which
		// real CAS base URL to point the CAS-facing proxy at), not cached
		// user data - withholding it under -no-cache would leave
		// UpstreamCASBaseURL permanently unanswered, 503ing every CAS
		// request even though every Hub call is still relayed live.
		s.casURLCache.Set(casURLCacheKey, tok.CasURL)
	}

	// Remember which credential minted this access token so a later
	// CAS-port 401 presenting it can be healed with a fresh replacement
	// (FreshXetTokenFor). Recording the token actually served - fresh or
	// stale - is deliberate: a client handed a stale token and presenting
	// it to the CAS is exactly the case the heal must be able to fix.
	s.recordAccessToken(tok.AccessToken, tokenRecord{
		cred: cred, cacheKey: key, repoType: repoType, repoID: repoID, revision: revision, kind: kind,
	})

	rewritten := *tok
	rewritten.CasURL = s.CASBaseURL

	w.Header().Set("X-Xet-Cas-Url", s.CASBaseURL)
	w.Header().Set("X-Xet-Access-Token", rewritten.AccessToken)
	w.Header().Set("X-Xet-Token-Expiration", strconv.FormatInt(rewritten.Exp, 10))
	writeJSON(w, rewritten)
}

// UpstreamCASBaseURL returns the most recently observed real upstream
// CAS base URL, or "" if none has been seen yet. Only ever reads
// present, never fresh - this cache has no periodic re-check to
// perform (the value only ever changes as a side effect of a real
// xet-token relay above, not on any TTL-driven schedule), so the ttl
// argument to Get is inert here; -1 makes that explicit rather than
// implying s.CacheTTL is meaningfully in play.
func (s *Server) UpstreamCASBaseURL() (string, bool) {
	value, present, _ := s.casURLCache.Get(casURLCacheKey, -1)
	return value, present
}

// fetchTokenCache is the xet-token-specific cache policy. It is stricter
// than the generic stale-fallback used for public metadata:
//
//   - An upstream 401/403 is never hidden behind a cached token. The
//     credential in the cache key is the caller's own, so a wrong/expired
//     credential gets its own (normally empty) entry and must see the
//     upstream rejection, not a token minted for someone else.
//   - A network/hang/malformed-JSON failure may still serve this same
//     credential's cached, unexpired token - that is the proxy's offline
//     resilience, and it cannot cross principals because the cache key
//     includes the credential fingerprint.
//   - A cached token within tokenSafetyMargin of expiry is treated as
//     unusable even on the stale path, matching huggingface_hub's own
//     freshness rule.
func fetchTokenCache(noCache bool, cache *ttlCache[*hfclient.XetToken], ttl time.Duration, key string, fetch func() (*hfclient.XetToken, error)) (*hfclient.XetToken, error) {
	if noCache {
		return fetch()
	}
	if value, present, fresh := cache.Get(key, ttl); present && fresh && tokenUsable(value) {
		return value, nil
	}
	value, err := fetch()
	if err != nil {
		if isAuthFailure(err) {
			return nil, err
		}
		if stale, present, _ := cache.Get(key, ttl); present && tokenUsable(stale) {
			return stale, nil
		}
		return nil, err
	}
	cache.Set(key, value)
	return value, nil
}

func tokenUsable(t *hfclient.XetToken) bool {
	return t != nil && t.Exp > time.Now().Add(tokenSafetyMargin).Unix()
}

// isAuthFailure reports whether err is an upstream 401/403. Those must
// never be hidden by a stale cache - doing so is exactly how a caller
// without access would receive another caller's token or private-repo
// metadata instead of the rejection the Hub already made.
func isAuthFailure(err error) bool {
	var statusErr *hfclient.StatusError
	return errors.As(err, &statusErr) && (statusErr.Status == http.StatusUnauthorized || statusErr.Status == http.StatusForbidden)
}

// tokenRecord remembers the exact Hub call parameters (and the caller's
// credential) that minted a given xet access token, so a later CAS-port 401
// presenting that token can be healed with a fresh replacement scoped to the
// same repo/ref (see FreshXetTokenFor).
type tokenRecord struct {
	cred     auth.CredentialHelper
	cacheKey string
	repoType string
	repoID   string
	revision string
	kind     hfclient.XetTokenKind
}

// maxIndexedAccessTokens bounds accessTokenIndex, which otherwise grows with
// every distinct token the proxy relays. Generous for any realistic mix of
// concurrent repos/refs; beyond it the oldest-recorded entry is evicted.
const maxIndexedAccessTokens = 4096

// recordAccessToken indexes presentedToken -> the tokenRecord that minted it,
// evicting an arbitrary entry once the index is full.
func (s *Server) recordAccessToken(presentedToken string, rec tokenRecord) {
	if presentedToken == "" {
		return
	}
	s.accessTokenMu.Lock()
	defer s.accessTokenMu.Unlock()
	if len(s.accessTokenIndex) >= maxIndexedAccessTokens {
		for k := range s.accessTokenIndex {
			delete(s.accessTokenIndex, k)
			break
		}
	}
	s.accessTokenIndex[presentedToken] = rec
}

// FreshXetTokenFor mints a freshly-issued replacement xet access token for
// the repo/ref that presentedToken was originally issued to, authenticating
// to the real Hub with the SAME credential that client used to obtain the
// original token (stored by recordAccessToken when the token was relayed).
// ok=false - and the caller should relay the upstream 401 as-is - when
// presentedToken isn't a token this proxy relayed, or the refresh call to the
// real Hub fails (including a revoked/expired client credential). Because the
// replacement is minted with the client's own credential for the same
// repo/ref/scope, this can never widen anyone's access - it only restores
// access the client already held.
func (s *Server) FreshXetTokenFor(ctx context.Context, presentedToken string) (string, bool) {
	s.accessTokenMu.Lock()
	rec, ok := s.accessTokenIndex[presentedToken]
	s.accessTokenMu.Unlock()
	if !ok {
		return "", false
	}
	callCtx := ctx
	cancel := func() {}
	if s.MetadataCallTimeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, s.MetadataCallTimeout)
	}
	defer cancel()
	fresh, err := s.Hub.GetXetToken(callCtx, rec.cred, rec.repoType, rec.repoID, rec.revision, rec.kind)
	if err != nil {
		slog.Warn("proxyhub: token-heal refresh failed", "repo", rec.repoID, "error", err)
		return "", false
	}
	// Keep the caches the rest of this proxy reads consistent with the
	// replacement token: the xet-token cache entry (so a future refresh
	// serves the fresh value) and the upstream CAS URL routing state.
	s.xetTokenCache.Set(rec.cacheKey, fresh)
	if fresh.CasURL != "" {
		s.casURLCache.Set(casURLCacheKey, fresh.CasURL)
	}
	s.recordAccessToken(fresh.AccessToken, rec)
	return fresh.AccessToken, true
}
