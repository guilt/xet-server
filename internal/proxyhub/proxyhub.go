// Package proxyhub implements the Hub-facing side of a caching
// pull-through proxy for the real huggingface.co Hub REST API, by
// EMBEDDING a real internal/hubserver.Server as its serving engine -
// mirroring internal/proxycas's design for the CAS side (see its
// package doc comment for the full rationale on why embedding a real,
// already-tested server beats reimplementing repo/revision/file state
// independently).
//
// For repo-info/tree/resolve (the read paths), this package's job is:
// check whether the embedded Server already has fresh-enough local
// state (via Has*, gated by a per-endpoint freshness timestamp - see
// cache.go); if so, delegate straight to Embedded.ServeHTTP with no
// upstream call at all. On a miss or once -cache-ttl's freshness window
// lapses, fetch from upstream (via internal/hfclient), feed the result
// into Embedded via Ingest* (see hubserver.Server's own doc comments on
// IngestRepoInfo/IngestFile/IngestCommit), then delegate. Critically,
// ANY upstream failure (network error, 5xx, timeout) falls back to
// whatever Embedded already has, no matter how old, rather than
// erroring - this fallback rule is this package's entire reason to
// exist: letting `hf download`/`hf upload` keep working against
// metadata already seen once, even after huggingface.co goes away for
// good. See docs/MIRRORING.md's offline-resilient-mirror use case.
//
// -cache-ttl controls freshness only, not eviction: within the TTL
// window a request is served entirely from Embedded with no upstream
// call at all; once the window lapses, a live refresh is attempted, but
// the fallback-on-failure rule above still applies. The default, -1,
// disables the freshness window entirely - every request attempts a
// live refresh first and falls back to Embedded only on failure.
//
// Xet-token is the one read endpoint that CANNOT be served via
// Embedded: hubserver's own xet-token handler mints a fake random
// token, which is worthless for authenticating against the real
// upstream CAS. This package instead caches the real XetToken value
// itself (CasURL rewritten to this proxy's own CAS-facing address,
// AccessToken passed through completely unchanged - pure credential
// passthrough) under the same freshness+fallback policy, entirely
// independent of Embedded - see token.go.
//
// Writes (repo/branch creation, commit, preupload) are always relayed
// to the real Hub write-through (only it can accept a real commit), and
// the exact same upstream response is written back to the caller; the
// write's effect is separately (and non-fatally) mirrored into Embedded
// via Ingest*, so a subsequent read of the same data is already a local
// hit.
package proxyhub

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/hfclient"
	"github.com/guilt/xet-server/internal/hubserver"
	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/ratelimit"
)

// Server wraps an embedded *hubserver.Server, filling it from upstream
// on demand. See the package doc comment for the overall design.
type Server struct {
	// Hub is the upstream client for the real Hub API.
	Hub *hfclient.Client

	// Embedded is the real serving engine for repo-info/tree/resolve -
	// exported so a caller (cmd/xet-proxyd) can call its own
	// Snapshot/LoadSnapshot directly. Embedded needs a "CAS" to bridge a
	// file's plain SHA-256/XetHash to a verified size (see hubserver.
	// Server.CAS's doc comment) - this package has no CAS server of its
	// own, so Server itself implements that interface, backed by
	// fileSizeByXetHash below (see XetHashForSHA256/FileSize's own doc
	// comment on why that's not fabricating anything).
	Embedded *hubserver.Server

	// CASBaseURL is this proxy's own CAS-facing address - substituted
	// for the real upstream CasURL in every xet-token response. See
	// token.go.
	CASBaseURL string

	mux *http.ServeMux

	// NoCache disables all caching (the -no-cache flag's effect): every
	// request is relayed live, Embedded is never read or written, and a
	// live failure is a live failure - no stale fallback.
	NoCache bool

	// CacheTTL is the -cache-ttl flag's value: how long already-ingested
	// local state is served without attempting an upstream refresh
	// first. Negative (the default, -1) disables the freshness window -
	// every request still attempts a live refresh first, falling back
	// to Embedded's state (regardless of age) only on failure.
	CacheTTL time.Duration

	// MetadataCallTimeout bounds each individual upstream Hub call this
	// package makes - repo-info/tree/resolve/xet-token are all small,
	// fixed-shape JSON/header responses that should never legitimately
	// take long; a slow-drip response (one that starts within
	// hfclient's own Transport-level ResponseHeaderTimeout but then
	// trickles bytes slowly) is not bounded by that alone. Since every
	// read path in this package already falls back to Embedded's cached
	// state on ANY upstream failure (see the package doc comment),
	// applying this timeout only ever makes that correct fallback
	// trigger sooner - it never turns a call that would have succeeded
	// into a failure the caller has to handle differently. Defaults to
	// callDefaultTimeout; a caller (cmd/xet-proxyd) may lower or raise
	// it, though there's rarely a reason to for a JSON-sized response.
	MetadataCallTimeout time.Duration

	repoInfoFreshness *ttlCache[struct{}]
	treeFreshness     *ttlCache[struct{}]
	resolveFreshness  *ttlCache[struct{}]

	xetTokenCache *ttlCache[*hfclient.XetToken]
	casURLCache   *ttlCache[string]

	// accessTokenIndex maps a relayed xet access token back to the Hub
	// call parameters (and the caller's credential) that minted it, so a
	// CAS-port 401 presenting that token can be healed transparently with
	// a fresh replacement - see token.go's FreshXetTokenFor. Guarded by
	// accessTokenMu.
	accessTokenMu    sync.Mutex
	accessTokenIndex map[string]tokenRecord

	// fileSizeByXetHash records the size upstream itself declared for a
	// given Xet hash (via a resolve or tree-listing response, both of
	// which carry it directly) - read back by FileSize below to answer
	// Embedded's own CAS-bridge lookup during a local resolve. This is
	// never a fabricated or guessed value: it's the exact number
	// upstream already told this proxy once, remembered so the same
	// answer can be given again without a repeat upstream call. Guarded
	// by fileSizeMu.
	fileSizeMu        sync.RWMutex
	fileSizeByXetHash map[merklehash.Hash]int64

	// configMu guards authenticator/rateLimiter, read on every request
	// while their setters may replace them at runtime.
	configMu sync.RWMutex

	authenticator auth.Authenticator

	// rateLimiter, if set via SetRateLimiter, gates every route in this
	// package by source IP - nil (the default) means unlimited. Same
	// broader-than-casserver-upload-only rationale as proxycas.Server.
	// rateLimiter (see its doc comment): every route here, including
	// reads, can trigger a real outbound call to the real Hub on a cache
	// miss.
	rateLimiter *ratelimit.Limiter
}

const casURLCacheKey = "cas-url"

// callDefaultTimeout is MetadataCallTimeout's default - generous for a
// small JSON/header response over a normal connection, short enough
// that a slow-drip upstream response doesn't hold this package's own
// stale-fallback path waiting any longer than necessary.
const callDefaultTimeout = 30 * time.Second

// New returns a Server relaying to the real Hub at hubBaseURL (falling
// back to hfclient.DefaultHubURL if empty) and rewriting xet-token
// responses to point at casBaseURL, this proxy's own CAS-facing
// address.
func New(hubBaseURL, casBaseURL string) *Server {
	s := &Server{
		Hub:                 hfclient.New(hubBaseURL),
		CASBaseURL:          casBaseURL,
		mux:                 http.NewServeMux(),
		CacheTTL:            -1,
		MetadataCallTimeout: callDefaultTimeout,
		repoInfoFreshness:   newTTLCache[struct{}](),
		treeFreshness:       newTTLCache[struct{}](),
		resolveFreshness:    newTTLCache[struct{}](),
		xetTokenCache:       newTTLCache[*hfclient.XetToken](),
		casURLCache:         newTTLCache[string](),
		accessTokenIndex:    make(map[string]tokenRecord),
		fileSizeByXetHash:   make(map[merklehash.Hash]int64),
		authenticator:       auth.NoAuth{},
	}
	s.Embedded = hubserver.New(casBaseURL, s)
	s.routes()
	return s
}

// callContext returns a context derived from r's own (bounded by
// MetadataCallTimeout, unless it's <= 0, in which case r's own context
// is used unmodified - an explicit escape hatch for a caller that wants
// no additional bound beyond the inbound request's own lifetime). The
// returned cancel func must be called once the upstream call this
// context guards has returned, same as any context.WithTimeout.
func (s *Server) callContext(r *http.Request) (context.Context, context.CancelFunc) {
	if s.MetadataCallTimeout <= 0 {
		return r.Context(), func() {}
	}
	return context.WithTimeout(r.Context(), s.MetadataCallTimeout)
}

// XetHashForSHA256 implements half of hubserver's casInfo interface -
// Embedded needs a "CAS" to bridge a committed file's plain SHA-256 to
// its Xet hash (see hubserver.Server.CAS's doc comment), but this proxy
// has no CAS server of its own to point it at. Every file this package
// ever ingests already carries its XetHash directly when known (learned
// from an upstream tree/resolve response - see repo.go/tree.go/
// resolve.go's IngestFile calls), so hubserver's own resolve handler
// uses that directly and never needs this bridge at all for such a
// file; this exists only to satisfy the interface for the (never
// exercised, by this package) zero-XetHash case, correctly reporting
// "unknown" rather than fabricate an answer.
func (s *Server) XetHashForSHA256(string) (merklehash.Hash, bool) { return merklehash.Hash{}, false }

// ReconstructFile completes casInfo for hubserver's git-lfs download
// bridge, which needs a CAS that can assemble a file from xorbs. This
// proxy holds no xorbs of its own (its CAS side is a pass-through cache,
// see internal/proxycas), so the bridge is not available through it:
// point git-lfs at a real xetd instead.
func (s *Server) ReconstructFile(context.Context, merklehash.Hash, int64, int64, io.Writer) error {
	return errors.New("proxyhub: git-lfs downloads are not served through the proxy; use a xetd instance")
}

// MissingXorbs completes casInfo alongside ReconstructFile; the proxy
// holds no xorbs, so the answer is the same "not served here".
func (s *Server) MissingXorbs(context.Context, merklehash.Hash) ([]merklehash.Hash, error) {
	return nil, errors.New("proxyhub: git-lfs downloads are not served through the proxy; use a xetd instance")
}

// FileSize implements the other half of casInfo - answering, for a
// given Xet hash, the file's verified size. Backed by
// fileSizeByXetHash: never a fabricated or guessed value, just the
// exact size upstream itself already declared for this hash in a
// resolve/tree-listing response (see IngestFileSize), remembered so the
// same answer can be given again without a repeat upstream call.
func (s *Server) FileSize(xetHash merklehash.Hash) (int64, bool) {
	s.fileSizeMu.RLock()
	defer s.fileSizeMu.RUnlock()
	size, ok := s.fileSizeByXetHash[xetHash]
	return size, ok
}

// recordFileSize records size as xetHash's verified size, for FileSize
// to answer later. Called by every IngestFile call site in this package
// that has a real, non-zero xetHash and a size to go with it.
func (s *Server) recordFileSize(xetHash merklehash.Hash, size int64) {
	if xetHash.IsZero() {
		return
	}
	s.fileSizeMu.Lock()
	s.fileSizeByXetHash[xetHash] = size
	s.fileSizeMu.Unlock()
}

// SetAuthenticator gates this package's own handlers (see
// authenticator's doc comment on proxycas.Server for why this package
// needs its own copy, checked before any upstream call - the same
// reasoning applies here) AND forwards to Embedded, so its own scope
// checks stay in sync.
func (s *Server) SetAuthenticator(a auth.Authenticator) {
	s.configMu.Lock()
	s.authenticator = a
	s.configMu.Unlock()
	s.Embedded.SetAuthenticator(a)
}

// SetRateLimiter installs a per-source-IP rate limiter in front of
// EVERY route this package serves - see rateLimiter's doc comment on
// why that's broader than casserver.Server.SetUploadRateLimiter's
// upload-only scope. Does NOT forward to Embedded: a caller wanting
// Embedded's own upload rate limiting too should configure it
// separately via s.Embedded.SetUploadRateLimiter, same as
// proxycas.Server.SetRateLimiter's contract.
func (s *Server) SetRateLimiter(l *ratelimit.Limiter) {
	s.configMu.Lock()
	s.rateLimiter = l
	s.configMu.Unlock()
}

func (s *Server) authenticatorSnapshot() auth.Authenticator {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.authenticator
}

func (s *Server) rateLimiterSnapshot() *ratelimit.Limiter {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.rateLimiter
}

// requireScope authenticates r against s.authenticator and checks for
// scope, writing a 401/403 and returning false if the request should
// not proceed to any upstream fetch/ingest.
func (s *Server) requireScope(w http.ResponseWriter, r *http.Request, scope auth.Scope) bool {
	principal, err := s.authenticatorSnapshot().Authenticate(r)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			httpErrorJSON(w, "unauthenticated: "+err.Error(), http.StatusUnauthorized)
		} else {
			httpErrorJSON(w, "authentication failed: "+err.Error(), http.StatusForbidden)
		}
		return false
	}
	if !principal.HasScope(scope) {
		httpErrorJSON(w, "principal lacks required scope: "+string(scope), http.StatusForbidden)
		return false
	}
	return true
}

// gate authenticates r for scope, then (if a rate limiter is
// configured) checks the per-source-IP rate limit, running next only if
// both pass - same auth-before-rate-limit order as
// proxycas.Server.gate/casserver.Server.routes' own upload-limiter
// wrapping, so an unauthenticated flood never consumes another client's
// rate-limit budget by sharing its source IP. Unlike proxycas, this
// package has no single mux-building gate wrapper to fold this into (see
// the package doc comment on handleAPIGet/handleAPIPost/
// handleResolveDispatch's own inline per-case requireScope calls), so
// each of those call sites replaces its own "if !s.requireScope(...)
// { return }" with "if !s.gate(w, r, scope) { return }".
func (s *Server) gate(w http.ResponseWriter, r *http.Request, scope auth.Scope) bool {
	if !s.requireScope(w, r, scope) {
		return false
	}
	limiter := s.rateLimiterSnapshot()
	if limiter == nil {
		return true
	}
	if !limiter.AllowRequest(r) {
		w.Header().Set("Retry-After", strconv.Itoa(limiter.RetryAfterSecondsForRequest(r)))
		httpErrorJSON(w, "rate limit exceeded", http.StatusTooManyRequests)
		return false
	}
	return true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) routes() {
	mux := http.NewServeMux()
	mux.Handle("GET /api/{rest...}", http.HandlerFunc(s.handleAPIGet))
	mux.Handle("POST /api/{rest...}", http.HandlerFunc(s.handleAPIPost))
	mux.Handle("/{rest...}", http.HandlerFunc(s.handleResolveDispatch))
	s.mux = mux
}

// splitRepoPath is proxyhub's own copy of hubserver.splitRepoPath -
// duplicated (not imported) since it's an unexported helper of a
// package this one only otherwise touches through its exported
// Ingest*/Has*/ServeHTTP surface.
func splitRepoPath(rest string) (repoType, repoID string, tail []string, ok bool) {
	parts := strings.Split(rest, "/")
	if len(parts) < 3 {
		return "", "", nil, false
	}
	repoTypePlural := parts[0]
	repoType = strings.TrimSuffix(repoTypePlural, "s")
	repoID = parts[1] + "/" + parts[2]
	return repoType, repoID, parts[3:], true
}

func (s *Server) handleAPIGet(w http.ResponseWriter, r *http.Request) {
	repoType, repoID, tail, ok := splitRepoPath(r.PathValue("rest"))
	if !ok || len(tail) < 2 {
		http.NotFound(w, r)
		return
	}
	switch tail[0] {
	case "xet-read-token":
		if !s.gate(w, r, auth.ScopeRead) {
			return
		}
		s.handleXetToken(w, r, repoType, repoID, tail[1], hfclient.XetTokenRead)
	case "xet-write-token":
		if !s.gate(w, r, auth.ScopeWrite) {
			return
		}
		s.handleXetToken(w, r, repoType, repoID, tail[1], hfclient.XetTokenWrite)
	case "revision":
		if !s.gate(w, r, auth.ScopeRead) {
			return
		}
		s.handleRepoInfo(w, r, repoType, repoID, tail[1])
	case "tree":
		if !s.gate(w, r, auth.ScopeRead) {
			return
		}
		var pathInRepo string
		if len(tail) > 2 {
			pathInRepo = strings.Join(tail[2:], "/")
		}
		s.handleListTree(w, r, repoType, repoID, tail[1], pathInRepo)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleAPIPost(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	if rest == "repos/create" {
		if !s.gate(w, r, auth.ScopeWrite) {
			return
		}
		s.handleCreateRepo(w, r)
		return
	}
	repoType, repoID, tail, ok := splitRepoPath(rest)
	if !ok || len(tail) < 2 {
		http.NotFound(w, r)
		return
	}
	revision := tail[1]
	switch tail[0] {
	case "commit":
		if !s.gate(w, r, auth.ScopeWrite) {
			return
		}
		s.handleCommit(w, r, repoType, repoID, revision)
	case "preupload":
		if !s.gate(w, r, auth.ScopeWrite) {
			return
		}
		s.handlePreupload(w, r, repoType, repoID, revision)
	case "branch":
		if !s.gate(w, r, auth.ScopeWrite) {
			return
		}
		s.handleCreateBranch(w, r, repoType, repoID, revision)
	default:
		http.NotFound(w, r)
	}
}

// handleResolveDispatch handles GET/HEAD resolve requests (three URL
// shapes: bare owner/name for models, "datasets/owner/name" for datasets,
// "spaces/owner/name" for spaces - see hubserver.parseResolvePath's doc
// comment on why parse-from-the-right handles all three plus any future
// repo-type prefix a real Hub URL adds) and relays every other Git LFS
// path (batch, objects) live to the real Hub: this proxy implements the
// Xet protocol, not LFS, so it must pass those through transparently
// rather than 404 them (a real `hf upload` of a small file hits the
// batch endpoint immediately, and the client's own reconstruction of an
// LFS-backed file may follow /{repo}.git/objects/ links).
func (s *Server) handleResolveDispatch(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, ".git/info/lfs") || strings.Contains(r.URL.Path, ".git/objects") {
		s.relayHubLive(w, r)
		return
	}
	repoType, repoID, revision, filename, ok := parseResolvePath(r.PathValue("rest"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !s.gate(w, r, auth.ScopeRead) {
		return
	}
	s.handleResolve(w, r, repoType, repoID, revision, filename)
}

// parseResolvePath finds the "/resolve/" marker in rest and returns the
// two path segments IMMEDIATELY before it as repoID (namespace/name),
// with revision and filename taken from AFTER the marker, and repoType
// derived from whatever segment precedes the namespace ("datasets" ->
// "dataset", "spaces" -> "space", nothing -> "model"). Parsing from the
// right means any future repo-type prefix a real Hub URL adds is
// accepted without a code change here. Duplicated verbatim in hubserver
// for the same reason as splitRepoPath (see its note above): an
// unexported helper of a package this one only otherwise touches through
// its exported surface.
func parseResolvePath(rest string) (repoType, repoID, revision, filename string, ok bool) {
	const marker = "/resolve/"
	idx := strings.Index(rest, marker)
	if idx < 0 {
		return "", "", "", "", false
	}
	headParts := strings.Split(rest[:idx], "/")
	if len(headParts) < 2 {
		return "", "", "", "", false
	}
	// Both repo-ID segments must be non-empty - see hubserver's copy for
	// the "//resolve//0" case this rejects (found by fuzzing).
	namespace, name := headParts[len(headParts)-2], headParts[len(headParts)-1]
	if namespace == "" || name == "" {
		return "", "", "", "", false
	}
	repoID = namespace + "/" + name
	repoType = repoTypeFromPrefix(headParts[:len(headParts)-2])
	tail := rest[idx+len(marker):]
	slash := strings.Index(tail, "/")
	if slash < 0 {
		return "", "", "", "", false
	}
	revision = tail[:slash]
	filename = tail[slash+1:]
	if revision == "" || filename == "" {
		return "", "", "", "", false
	}
	return repoType, repoID, revision, filename, true
}

// repoTypeFromPrefix maps a resolve URL's leading segments (everything
// before {namespace}/{name}) to a singular repo type. Models carry no
// prefix at all; datasets and spaces carry exactly one pluralized
// segment. Anything else (empty, or an unrecognised future prefix) falls
// back to "model", matching huggingface_hub's own default repo_type.
func repoTypeFromPrefix(prefix []string) string {
	if len(prefix) == 0 {
		return "model"
	}
	switch prefix[len(prefix)-1] {
	case "datasets":
		return "dataset"
	case "spaces":
		return "space"
	default:
		return "model"
	}
}

// httpErrorJSON writes a JSON HTTP error, logging it at a level matching
// its cause - same convention as hubserver.httpErrorJSON/casserver.
// httpError: a 5xx (this proxy's own fault, or an upstream failure it's
// relaying) is worth surfacing at Warn by default, while a 4xx (a client
// protocol/input error, expected under normal operation) logs at Debug
// only, so it doesn't spam the default log level.
func httpErrorJSON(w http.ResponseWriter, msg string, code int) {
	if code >= 500 {
		slog.Warn("proxyhub: request failed", "status", code, "error", msg)
	} else {
		slog.Debug("proxyhub: request rejected", "status", code, "error", msg)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": msg}); err != nil {
		slog.Error("proxyhub: encode response", "error", err)
	}
}

// writeUpstreamError maps err from an hfclient call onto the downstream
// response: a *hfclient.StatusError carries the real upstream status
// (and X-Error-Code, if any) and is relayed as-is; anything else (a
// network failure) is a 502.
func writeUpstreamError(w http.ResponseWriter, err error) {
	var statusErr *hfclient.StatusError
	if errors.As(err, &statusErr) {
		if statusErr.ErrorCode != "" {
			w.Header().Set("X-Error-Code", statusErr.ErrorCode)
		}
		if len(statusErr.Body) > 0 {
			// Relay the real upstream error body verbatim rather than a
			// reformatted proxy message: real clients parse fields out of
			// it. huggingface_hub's create_repo, for example, tolerates a
			// 409 "already exists" under exist_ok=True by reading the
			// response's `url` field (d["url"]) - a proxy-generated
			// {"error": ...} body without that field breaks it.
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusErr.Status)
			w.Write(statusErr.Body)
			return
		}
		httpErrorJSON(w, err.Error(), statusErr.Status)
		return
	}
	httpErrorJSON(w, "upstream request failed: "+err.Error(), http.StatusBadGateway)
}

// trimQuotes strips one leading and one trailing '"' from s, if both are
// present - real Hub ETags (and this package's own hfclient.ResolveInfo.
// ETag, which just forwards the raw header value) are quoted strings;
// hubserver's own fileRef.SHA256Hex is stored WITHOUT quotes and gets
// requoted when handleResolve builds the ETag header - so ingesting a
// file learned from a resolve response must strip them first to store
// the same underlying value hubserver's own commit path would have.
func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
