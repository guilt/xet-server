# `github.com/guilt/xet-server/internal/proxycas`

```
package proxycas // import "github.com/guilt/xet-server/internal/proxycas"

Package proxycas implements the CAS-facing side of a caching pull-through proxy
for the real Xet CAS backend, by EMBEDDING a real internal/casserver.Server
as its serving engine rather than reimplementing byte-range serving,
reconstruction-response building, footer/shard indexing, or snapshotting
independently - every one of those already exists, is already tested, and this
package's whole job is to keep it filled with data fetched from upstream,
not to grow a second copy of the same logic that has to be kept in sync by hand.

For each request, this package's job is: check whether the embedded
Server already has what's needed (via its Has*/Ingest* API - see
casserver.Server's own doc comments on IngestXorb/IngestShard/
IngestFileRecon/HasXorbFooter/HasXorbBytes/HasFileRecon); if so, delegate
straight to embedded.ServeHTTP with no upstream call at all - this is what makes
anything already cached fully offline-capable. On a miss, fetch the missing
piece from upstream (via internal/hfclient's CASClient, discovered per-repo
through internal/proxyhub's own xet-token handling - see WithCASClient), feed it
into the embedded Server through Ingest*, then delegate.

Reconstruction is the one place this needs real care: real production Xet's
fetch_info/xorbs URLs are presigned URLs pointing directly at blob storage, not
at the CAS server itself - casserver's own xorbFetchURL always returns its own
byte-serving endpoint (it has no notion of a presigned upstream URL), so simply
feeding an upstream reconstruction's raw xorb hashes into IngestFileRecon and
then delegating to embedded.ServeHTTP is already correct: the embedded server's
own reconstruction handler emits URLs pointing at ITSELF, which is exactly the
rewriting proxycas needs, for free. The one upstream Range-header subtlety
still applies here (see ensureFileReconCached's doc comment): a ranged upstream
response only contains that window's terms, so the FIRST fetch for a file must
always be for the whole thing, regardless of what the downstream caller actually
asked for - IngestFileRecon assumes a complete list.

A file often cites only part of a shared xorb (Xet dedups across files/repos).
Those bytes cannot reproduce the original xorb's hash, but they are still
a complete chunk stream: ensureFileReconCached repackages each contiguous
fetch_info group as a new xorb under its own content hash and rewrites the
file's terms to point at it. No partial slice is ever stored under the original
hash, and the file remains fully servable after the handoff to a plain xetd.
Only when fetch_info leaves a gap in a term's coverage does the request fall
back to a live relay (correctness is preserved, but that file is not cached).

-no-cache disables all of the above: every request is relayed live to upstream
via internal/hfclient directly, embedded is never touched.

FUNCTIONS

func WithCASClient(ctx context.Context, casClient *hfclient.CASClient) context.Context
    WithCASClient returns a copy of ctx carrying casClient, for handlers in
    this package to read via casClientFromContext. internal/proxyhub calls this
    (after resolving the repo's CAS endpoint via a Hub xet-token request) before
    forwarding a request into this server's ServeHTTP.

func WithTokenRefresher(ctx context.Context, refresher TokenRefresher) context.Context
    WithTokenRefresher returns a copy of ctx carrying refresher, for handlers in
    this package to read via tokenRefresherFromContext.


TYPES

type Server struct {
	// Embedded is the real serving engine - exported so a caller (e.g.
	// cmd/xet-proxyd) can call its own Snapshot/LoadSnapshot directly;
	// this package never needs its own snapshot format, since it has no
	// state of its own beyond what Embedded already tracks.
	Embedded *casserver.Server

	// NoCache disables all caching (the -no-cache flag's effect): every
	// request is relayed live to upstream via internal/hfclient, and
	// Embedded is never read or written. Off by default.
	NoCache bool

	// Has unexported fields.
}
    Server wraps an embedded *casserver.Server, filling it from upstream on
    demand. See the package doc comment for the overall design.

func New(xorbs storage.Store) *Server
    New creates a Server backed by xorbs for the embedded casserver.Server's
    local storage.

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request)

func (s *Server) SetAuthenticator(a auth.Authenticator)
    SetAuthenticator gates this package's own handlers (see authenticator's doc
    comment on why this package needs its own copy) AND forwards to the embedded
    casserver.Server, so casserver's own scope checks - the ones that actually
    run once a request is delegated - stay in sync.

func (s *Server) SetRateLimiter(l *ratelimit.Limiter)
    SetRateLimiter installs a per-source-IP rate limiter in front of EVERY route
    this package serves (see rateLimiter's doc comment on why that's broader
    than casserver.Server.SetUploadRateLimiter's upload-only scope). Unlike
    casserver's own SetUploadRateLimiter, this never rebuilds the mux - gate
    reads s.rateLimiter fresh on every request, so a later call takes effect
    immediately, matching this package's own SetAuthenticator/requireScope
    contract exactly. Does NOT forward to Embedded: casserver's own upload
    rate limiter is a distinct, narrower concern (guarding its own local
    CPU cost) that a caller wanting both should configure separately via
    s.Embedded.SetUploadRateLimiter.

type TokenRefresher interface {
	FreshXetTokenFor(ctx context.Context, presentedToken string) (freshToken string, ok bool)
}
    TokenRefresher mints a fresh replacement for an upstream xet access
    token the real CAS rejected. Implemented by internal/proxyhub.Server
    (FreshXetTokenFor) and installed into the request context by
    cmd/xet-proxyd's withUpstreamCASClient middleware; proxycas itself never
    constructs one, and never heals a 401 when none is wired in.
```
