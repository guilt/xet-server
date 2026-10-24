# `github.com/guilt/xet-server/internal/auth`

```
package auth // import "github.com/guilt/xet-server/internal/auth"

Package auth defines this project's authentication/authorization interfaces,
kept deliberately small so a third party can implement a custom backend (JWT,
OAuth, mTLS, an internal SSO integration, whatever a real deployment needs)
without touching casserver, hubserver, or the cmd/xet client at all - implement
Authenticator (server side) and/or CredentialHelper (client side), and both
sides of this project work with it automatically.

This mirrors the real xet-core/hf_xet protocol's actual auth model (confirmed
against xet-core's own openapi/cas.openapi.yaml and its client-side
xet_client::common::auth module): Authorization: Bearer <token>, with tokens
carrying scopes (read, write) - 401 for a missing or invalid token, 403 for a
valid token lacking the scope a given endpoint requires. See docs/PROTOCOL.md
for the full writeup.

The zero-configuration default on both sides (NoAuth, NoopCredentialHelper) is
byte-for-byte today's pre-v0.8.0 behavior: no token is required, and none is
sent. Passing -auth-token to xetd or xet is what opts into enforcement/sending
a credential - existing deployments and scripts that never pass that flag see no
behavior change at all.

CONSTANTS

const SharedSecretSubject = "shared-secret"
    SharedSecretSubject is the Subject reported for a request that authenticated
    with the raw shared secret and no user name.


VARIABLES

var ErrForbidden = errors.New("auth: principal lacks required scope")
    ErrForbidden is returned by Authenticate (via errors.Is) when the request's
    credential is valid but the resulting Principal lacks a scope the caller is
    about to check for. In practice this project's Authenticator implementations
    return a Principal from Authenticate and let the caller check HasScope
    itself (see casserver/hubserver's requireScope helper) - ErrForbidden
    exists for a custom Authenticator that prefers to reject at authentication
    time instead, and for callers that want one consistent sentinel for
    "authenticated but not allowed" regardless of which layer decided that.

var ErrUnauthenticated = errors.New("auth: request is not authenticated")
    ErrUnauthenticated is returned by Authenticate (via errors.Is) when the
    request carries no credential, or one the Authenticator cannot validate at
    all (wrong token, malformed header, expired token, etc.). Callers map this
    to HTTP 401.


FUNCTIONS

func AllowsRepo(p Principal, repo Repo) bool
    AllowsRepo reports whether p may act on repo. A repo-scoped principal
    must match repo exactly; an unrestricted principal (shared secret, NoAuth,
    StaticTokenAuth, custom) may act on any repo.

func AllowsRepoCreate(p Principal, repo Repo) bool
    AllowsRepoCreate reports whether p may create repo. Repo creation is the one
    operation whose target cannot already be covered by the token's own repo,
    so the rule is deliberately weaker than AllowsRepo: a repo-scoped write
    credential may create a new repo only inside its own namespace ("alice/sec"
    may create "alice/new"); creating in any other namespace requires the shared
    secret's admin scope. This stops a token minted for one repo from populating
    another owner's namespace.

func BearerToken(r *http.Request) string
    BearerToken extracts the token from an incoming request's "Authorization:
    Bearer <token>" header (case-insensitive scheme name per RFC 6750), or "" if
    the header is absent or not in that exact form. Exported (StaticTokenAuth
    uses the same logic internally) so a relay/proxy Authenticator can pull a
    caller's credential back out of a request it just authenticated, in order
    to forward that exact credential upstream via a CredentialHelper - the
    chaining primitive a passthrough proxy needs, as opposed to resolving its
    own independent, unrelated upstream secret.

func ResolveToken(flagValue string, envVars ...string) string
    ResolveToken returns flagValue if it was explicitly set to something other
    than empty or the sentinel "None" (this project's convention, used by every
    -auth-token flag, for "not passed on the command line"), otherwise returns
    the first non-empty value found among envVars, checked in the order given,
    otherwise returns flagValue unchanged (i.e. "None" or "").

    An explicit flag always wins over the environment, so an operator can still
    override a machine-wide/session-wide environment variable per invocation;
    the environment is checked before falling back to the flag's own zero
    value because a flag value is visible to any other local user via `ps
    -ef`/`/proc/<pid>/cmdline` and gets written to shell history, while an
    environment variable set through a secrets manager, a `.env` file kept out
    of history, or `read -s` is not.

    This is the one call shape every binary in this project uses to resolve
    its token: xetd calls auth.ResolveToken(*authToken, "XETD_AUTH_TOKEN",
    "HF_TOKEN") so its shared secret can fall back to the same $HF_TOKEN a user
    already has exported for the real `hf` CLI - a local xetd then "just works"
    as a drop-in replacement without configuring a second, separate secret.
    xet calls auth.ResolveToken(authToken, "XET_AUTH_TOKEN", "HF_TOKEN") for
    the same reason on the client side. A future relay/proxy (e.g. one that
    authenticates local callers and forwards their credential to the real
    huggingface.co Xet backend) resolves its own upstream credential with the
    identical call, just a different env var chain - no new primitive needed to
    support that case.


TYPES

type Authenticator interface {
	Authenticate(r *http.Request) (Principal, error)
}
    Authenticator validates an incoming HTTP request's credential and returns
    the Principal it maps to. Implementations should extract whatever credential
    their scheme uses (a bearer token, a client certificate, a signed cookie,
    ...) from r and validate it - r must not be mutated.

    A request with no credential at all is not a special case an Authenticator
    needs to detect separately: reading a missing Authorization header is
    indistinguishable from reading an empty one, and both should simply fail
    validation and return ErrUnauthenticated like any other invalid credential
    would.

type BearerCredentialHelper struct {
	// Has unexported fields.
}
    BearerCredentialHelper attaches "Authorization: Bearer <token>" to every
    request - the client-side counterpart to StaticTokenAuth.

func NewBearerCredentialHelper(token string) *BearerCredentialHelper
    NewBearerCredentialHelper constructs a BearerCredentialHelper sending token
    on every request it fills.

func (c *BearerCredentialHelper) FillCredential(req *http.Request) error

func (c *BearerCredentialHelper) WhoAmI() string

type CredentialHelper interface {
	// FillCredential attaches a credential to req in place (e.g. setting
	// an Authorization header) before it's sent. Returning an error
	// aborts the request - a helper that needs to fetch a token from
	// elsewhere first should report a failure to do so this way, rather
	// than silently sending an unauthenticated request.
	FillCredential(req *http.Request) error

	// WhoAmI returns a short identifier for logging (which credential
	// helper is active, not the identity it authenticates as - a bearer
	// helper doesn't necessarily know who its token belongs to).
	WhoAmI() string
}
    CredentialHelper is this project's client-side mirror of Authenticator:
    something that attaches whatever credential a server-side Authenticator
    expects to an outgoing request. Kept to exactly two methods, mirroring real
    xet-core's own xet_client::common::auth::CredentialHelper trait (confirmed
    against its source - see docs/PROTOCOL.md), so implementing a custom one
    (e.g. to fetch a short-lived token from an internal service before each
    request) is a small, self-contained task.

func CredentialFromRequest(r *http.Request) CredentialHelper
    CredentialFromRequest returns a CredentialHelper that forwards r's own
    "Authorization: Bearer <token>" header unchanged on an outgoing request
    (NoopCredentialHelper if r carries none) - the shared building block a
    relay/proxy (internal/proxycas, internal/proxyhub) uses to implement pure
    credential passthrough: whatever bearer token the calling client sent,
    forwarded upstream exactly as received, never replaced by a secret the proxy
    layer itself holds.

type NoAuth struct{}
    NoAuth is the default Authenticator: every request succeeds, and the
    returned Principal holds every scope unconditionally. This is exactly
    this project's pre-v0.8.0 behavior (no auth enforcement at all) -
    both casserver.Server and hubserver.Server use this by default until
    SetAuthenticator is called with something else, so existing code that never
    touches the new auth APIs is completely unaffected.

func (NoAuth) Authenticate(*http.Request) (Principal, error)

type NoopCredentialHelper struct{}
    NoopCredentialHelper attaches nothing. This is the default on the client
    side (cmd/xet), matching NoAuth on the server side - this project's
    pre-v0.8.0 behavior, unaffected unless -auth-token is explicitly passed.

func (NoopCredentialHelper) FillCredential(*http.Request) error

func (NoopCredentialHelper) WhoAmI() string

type Principal interface {
	// Subject returns an identifier for logging/auditing - a username,
	// token ID, service account name, whatever the Authenticator
	// considers meaningful. Not used for any authorization decision
	// itself; HasScope is.
	Subject() string

	// HasScope reports whether this Principal is authorized for scope.
	HasScope(scope Scope) bool
}
    Principal is the authenticated identity/permission set an Authenticator
    hands back for a request that passed authentication. Kept to exactly two
    methods so a minimal custom implementation (e.g. "this token maps to this
    one hardcoded scope set") costs almost nothing to write.

type Repo struct {
	Type string
	ID   string
}
    Repo identifies one repository a credential is scoped to. Type is
    the singular Hub repo type ("model", "dataset", "space") and ID is
    "{namespace}/{name}" - the same values the Hub routes parse out of their
    paths. The zero Repo means "not restricted to a repository": the shared
    secret, auth.NoAuth, and a custom Authenticator that does not implement
    RepoScopedPrincipal all behave that way.

func RepoOf(p Principal) Repo
    RepoOf returns p's repo restriction, or the zero Repo when p is not
    repo-scoped.

func (r Repo) IsZero() bool

func (r Repo) Namespace() string
    Namespace returns the owner part of ID ("alice" for "alice/model"). An ID
    with no slash is its own namespace.

func (r Repo) String() string

type RepoScopedPrincipal interface {
	Principal
	Repo() Repo
}
    RepoScopedPrincipal is implemented by a Principal whose credential is bound
    to exactly one repository - what SignedTokenAuth returns for a minted token.
    A Principal that does NOT implement it (the shared secret, auth.NoAuth,
    StaticTokenAuth) is unrestricted by repo; AllowsRepo treats it as valid for
    every repo, preserving the behavior of custom Authenticators that predate
    repo scoping.

type Scope string
    Scope identifies a capability a Principal may or may not hold. Kept as
    a plain string type (not a closed enum) so a custom Authenticator can
    introduce its own scopes beyond ScopeRead/ScopeWrite if its endpoints need
    finer-grained authorization than this project's built-in servers require.

const (
	// ScopeRead gates every read-only CAS/Hub endpoint (reconstruction,
	// xorb fetch, chunk-dedup lookup, resolve) - mirrors the real
	// protocol's `read` scope.
	ScopeRead Scope = "read"
	// ScopeWrite gates every mutating CAS/Hub endpoint (xorb/shard
	// upload, commit, repo create) - mirrors the real protocol's `write`
	// scope.
	ScopeWrite Scope = "write"
	// ScopeAdmin gates this project's own operator routes that destroy
	// data (garbage collection). Not part of the real protocol: no
	// minted token ever carries it, only the operator's shared secret
	// itself (SignedTokenAuth) or a deployment with no auth at all
	// (NoAuth, where every scope is granted).
	ScopeAdmin Scope = "admin"
)
type SignedTokenAuth struct {
	// Has unexported fields.
}
    SignedTokenAuth is the Authenticator a deployment with one shared secret
    should use when the Hub shim and the CAS run as a pair. It accepts three
    credential shapes:

      - Authorization: Bearer <secret> - the operator's shared secret, every
        scope (what StaticTokenAuth accepts).
      - Authorization: Basic <user>:<secret> - the same secret sent the only way
        git-lfs can send a credential (HTTP Basic, via git's credential helper).
        The user part becomes the Principal's Subject, which is what names the
        owner of a git-lfs lock.
      - Authorization: Bearer <minted token> - a token this same secret minted
        via MintToken: HMAC-signed, scoped (read or write), bound to a subject,
        expiring, and scoped to one repository. This is what the Hub shim hands
        to hf_xet / git-xet for the CAS, and what it puts on git-lfs download
        hrefs. Also accepted as the password of a Basic credential, since some
        clients can only send Basic.

    The repository binding is part of the MAC, not a separate check:
    a token minted for alice/one cannot be edited into one for bob/two, and Hub
    routes reject it when the repo in the URL does not match (see AllowsRepo).
    Tokens minted before this field existed (xst1) are refused outright rather
    than accepted unscoped.

    Minted tokens are stateless: any process holding the secret can verify one,
    so a CAS and a Hub shim in separate processes (or a restarted one) agree
    without sharing state. StaticTokenAuth stays as the plain single-secret
    Authenticator for deployments that never mint anything.

func NewSignedTokenAuth(secret string) *SignedTokenAuth
    NewSignedTokenAuth constructs a SignedTokenAuth around secret, which must be
    non-empty (see NewStaticTokenAuth for why an empty secret is refused rather
    than silently accepted).

func (a *SignedTokenAuth) Authenticate(r *http.Request) (Principal, error)
    Authenticate implements Authenticator; see the type's doc comment for the
    three accepted credential shapes.

func (a *SignedTokenAuth) MintToken(scope Scope, subject string, repo Repo, ttl time.Duration) (string, time.Time, error)
    MintToken implements TokenMinter. Layout (dot-separated, every field free of
    dots by construction - repo type/id are hex-encoded):

        xst2.<exp unix seconds>.<scope>.<hex(subject)>.<hex(repo type)>.<hex(repo id)>.<hex(HMAC-SHA256)>

    The MAC covers the prefix, expiry, scope, subject, repo type, and repo ID,
    so none of them can be altered without the secret. A zero repo produces the
    empty strings in the two repo fields; that shape is only used for the URL
    token the CAS mints when the caller authenticated with the shared secret
    itself (which is already unrestricted).

func (a *SignedTokenAuth) VerifyURLToken(token string) (Principal, error)
    VerifyURLToken implements URLTokenVerifier: a minted token is as good in a
    URL as in a header, since it already carries its scope, subject and expiry.

type StaticTokenAuth struct {
	// Has unexported fields.
}
    StaticTokenAuth is a single shared-secret Authenticator: exactly one bearer
    token, set at construction, grants full access (every scope) to any request
    presenting it; any other token, or none, fails with ErrUnauthenticated.
    This deliberately does not distinguish per-user identity or partial scopes
    - it's a single gate for the whole server, matching how this project's
    -auth-token flag is meant to be used (an operator-chosen shared secret,
    not a multi-tenant credential system). A deployment that needs real per-user
    scopes should implement its own Authenticator against whatever identity
    provider it already has; this type is intentionally the simplest possible
    non-trivial option, not the only one.

func NewStaticTokenAuth(token string) *StaticTokenAuth
    NewStaticTokenAuth constructs a StaticTokenAuth requiring exactly token.
    token must be non-empty - constructing this with an empty string would make
    every bearer-auth request (even one presenting an empty token, which some
    malformed clients do) succeed, defeating the point; use NoAuth{} directly if
    no enforcement is wanted.

func (a *StaticTokenAuth) Authenticate(r *http.Request) (Principal, error)

type TokenMinter interface {
	// MintToken returns a token granting scope to subject for repo until
	// exp. A zero repo mints an unscoped token; Hub routes always pass a
	// real repo, and a minted token is rejected on any Hub route whose
	// repo it does not match (see AllowsRepo).
	MintToken(scope Scope, subject string, repo Repo, ttl time.Duration) (token string, exp time.Time, err error)
}
    TokenMinter issues short-lived bearer tokens carrying a scope, a subject,
    and a repo binding. hubserver uses it to answer the xet-{read,write}-token
    routes and to put a token into every git-lfs batch action it hands out,
    so the CAS side can authenticate those requests without the client ever
    seeing the operator's shared secret.

type URLTokenVerifier interface {
	VerifyURLToken(token string) (Principal, error)
}
    URLTokenVerifier is implemented by an Authenticator that accepts a minted
    token carried in a URL's query string instead of a header: the credential
    of a presigned-style download URL. xet-core fetches the xorb URLs in a
    reconstruction response with no Authorization header (on the real Hub they
    are presigned CDN URLs), so a CAS whose storage backend cannot presign signs
    its own byte-serving URLs this way. Only casserver's xorb GET/HEAD routes
    consult it; nothing else accepts a credential from a URL.
```
