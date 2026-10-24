# `github.com/guilt/xet-server/internal/proxyhub`

```
package proxyhub // import "github.com/guilt/xet-server/internal/proxyhub"

Package proxyhub implements the Hub-facing side of a caching pull-through
proxy for the real huggingface.co Hub REST API, by EMBEDDING a real
internal/hubserver.Server as its serving engine - mirroring internal/proxycas's
design for the CAS side (see its package doc comment for the full rationale
on why embedding a real, already-tested server beats reimplementing
repo/revision/file state independently).

For repo-info/tree/resolve (the read paths), this package's job is: check
whether the embedded Server already has fresh-enough local state (via Has*,
gated by a per-endpoint freshness timestamp - see cache.go); if so,
delegate straight to Embedded.ServeHTTP with no upstream call at all.
On a miss or once -cache-ttl's freshness window lapses, fetch from upstream
(via internal/hfclient), feed the result into Embedded via Ingest* (see
hubserver.Server's own doc comments on IngestRepoInfo/IngestFile/IngestCommit),
then delegate. Critically, ANY upstream failure (network error, 5xx,
timeout) falls back to whatever Embedded already has, no matter how old, rather
than erroring - this fallback rule is this package's entire reason to exist:
letting `hf download`/`hf upload` keep working against metadata already seen
once, even after huggingface.co goes away for good. See docs/MIRRORING.md's
offline-resilient-mirror use case.

-cache-ttl controls freshness only, not eviction: within the TTL window a
request is served entirely from Embedded with no upstream call at all; once the
window lapses, a live refresh is attempted, but the fallback-on-failure rule
above still applies. The default, -1, disables the freshness window entirely -
every request attempts a live refresh first and falls back to Embedded only on
failure.

Xet-token is the one read endpoint that CANNOT be served via Embedded:
hubserver's own xet-token handler mints a fake random token, which is worthless
for authenticating against the real upstream CAS. This package instead caches
the real XetToken value itself (CasURL rewritten to this proxy's own CAS-facing
address, AccessToken passed through completely unchanged - pure credential
passthrough) under the same freshness+fallback policy, entirely independent of
Embedded - see token.go.

Writes (repo/branch creation, commit, preupload) are always relayed to the
real Hub write-through (only it can accept a real commit), and the exact
same upstream response is written back to the caller; the write's effect is
separately (and non-fatally) mirrored into Embedded via Ingest*, so a subsequent
read of the same data is already a local hit.

TYPES

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

	// Has unexported fields.
}
    Server wraps an embedded *hubserver.Server, filling it from upstream on
    demand. See the package doc comment for the overall design.

func New(hubBaseURL, casBaseURL string) *Server
    New returns a Server relaying to the real Hub at hubBaseURL (falling back to
    hfclient.DefaultHubURL if empty) and rewriting xet-token responses to point
    at casBaseURL, this proxy's own CAS-facing address.

func (s *Server) FileSize(xetHash merklehash.Hash) (int64, bool)
    FileSize implements the other half of casInfo - answering, for a given
    Xet hash, the file's verified size. Backed by fileSizeByXetHash:
    never a fabricated or guessed value, just the exact size upstream itself
    already declared for this hash in a resolve/tree-listing response (see
    IngestFileSize), remembered so the same answer can be given again without a
    repeat upstream call.

func (s *Server) FreshXetTokenFor(ctx context.Context, presentedToken string) (string, bool)
    FreshXetTokenFor mints a freshly-issued replacement xet access token for the
    repo/ref that presentedToken was originally issued to, authenticating to the
    real Hub with the SAME credential that client used to obtain the original
    token (stored by recordAccessToken when the token was relayed). ok=false -
    and the caller should relay the upstream 401 as-is - when presentedToken
    isn't a token this proxy relayed, or the refresh call to the real Hub fails
    (including a revoked/expired client credential). Because the replacement
    is minted with the client's own credential for the same repo/ref/scope,
    this can never widen anyone's access - it only restores access the client
    already held.

func (s *Server) MissingXorbs(context.Context, merklehash.Hash) ([]merklehash.Hash, error)
    MissingXorbs completes casInfo alongside ReconstructFile; the proxy holds no
    xorbs, so the answer is the same "not served here".

func (s *Server) ReconstructFile(context.Context, merklehash.Hash, int64, int64, io.Writer) error
    ReconstructFile completes casInfo for hubserver's git-lfs download bridge,
    which needs a CAS that can assemble a file from xorbs. This proxy
    holds no xorbs of its own (its CAS side is a pass-through cache, see
    internal/proxycas), so the bridge is not available through it: point git-lfs
    at a real xetd instead.

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request)

func (s *Server) SetAuthenticator(a auth.Authenticator)
    SetAuthenticator gates this package's own handlers (see authenticator's doc
    comment on proxycas.Server for why this package needs its own copy, checked
    before any upstream call - the same reasoning applies here) AND forwards to
    Embedded, so its own scope checks stay in sync.

func (s *Server) SetRateLimiter(l *ratelimit.Limiter)
    SetRateLimiter installs a per-source-IP rate limiter in front of EVERY route
    this package serves - see rateLimiter's doc comment on why that's broader
    than casserver.Server.SetUploadRateLimiter's upload-only scope. Does NOT
    forward to Embedded: a caller wanting Embedded's own upload rate limiting
    too should configure it separately via s.Embedded.SetUploadRateLimiter,
    same as proxycas.Server.SetRateLimiter's contract.

func (s *Server) UpstreamCASBaseURL() (string, bool)
    UpstreamCASBaseURL returns the most recently observed real upstream CAS base
    URL, or "" if none has been seen yet. Only ever reads present, never fresh -
    this cache has no periodic re-check to perform (the value only ever changes
    as a side effect of a real xet-token relay above, not on any TTL-driven
    schedule), so the ttl argument to Get is inert here; -1 makes that explicit
    rather than implying s.CacheTTL is meaningfully in play.

func (s *Server) XetHashForSHA256(string) (merklehash.Hash, bool)
    XetHashForSHA256 implements half of hubserver's casInfo interface -
    Embedded needs a "CAS" to bridge a committed file's plain SHA-256 to its
    Xet hash (see hubserver.Server.CAS's doc comment), but this proxy has no
    CAS server of its own to point it at. Every file this package ever ingests
    already carries its XetHash directly when known (learned from an upstream
    tree/resolve response - see repo.go/tree.go/ resolve.go's IngestFile calls),
    so hubserver's own resolve handler uses that directly and never needs this
    bridge at all for such a file; this exists only to satisfy the interface
    for the (never exercised, by this package) zero-XetHash case, correctly
    reporting "unknown" rather than fabricate an answer.
```
