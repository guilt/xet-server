// Package hubserver implements just enough of huggingface.co's Hub REST
// API (distinct from the CAS API in internal/casserver) to let the real
// `hf upload` / `hf download` CLI commands (via huggingface_hub) work
// end-to-end against a local server, with HF_ENDPOINT pointed at it:
//
//   - POST /api/repos/create                                  - repo creation (idempotent)
//   - GET  /api/{repo_type}s/{repo_id}/xet-{read,write}-token/{revision}
//   - issues a CAS endpoint + bearer token via response headers
//   - POST /api/{repo_type}s/{repo_id}/commit/{revision}       - ndjson commit payload
//   - HEAD/GET /{repo_id}/resolve/{revision}/{filename}        - file metadata + content
//
// Each repo supports real, independent revisions (a "main" branch is
// created implicitly on first touch, matching how a real repo always has
// a default branch; any other revision name is created on first commit to
// it) - commit/resolve/preupload all operate against the named revision's
// own file set and commit history, not a single shared implicit state.
// No git refs/PRs are modeled. Every route except telemetry-equivalents
// (there are none in this shim) requires the scope real xet-core/Hub
// convention implies (write for token/commit/preupload/repo-create,
// read for resolve), enforced via auth.Authenticator - see
// SetAuthenticator. The default (auth.NoAuth{}) enforces nothing, this
// server's behavior prior to v0.8.0: any bearer token (or none) is
// accepted. State is held in memory alongside the paired
// casserver.Server, since a commit's file entries need to reference the
// Xet file hash the CAS layer already knows how to reconstruct - and
// periodically checkpointed to disk (see Server.Snapshot/LoadSnapshot in
// snapshot.go) so it survives a restart.
package hubserver

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/routing"
)

// casInfo is the subset of casserver.Server's read-side API this package
// needs, kept as a small local interface (rather than importing
// casserver.Server directly) so hubserver stays a thin, independently
// testable layer over whatever CAS backend it's paired with.
type casInfo interface {
	XetHashForSHA256(sha256Hex string) (merklehash.Hash, bool)
	FileSize(fileHash merklehash.Hash) (int64, bool)
	// ReconstructFile streams bytes [start, end] (inclusive) of the file
	// to w - the git-lfs download bridge (see lfsobjects.go) is the one
	// caller; real Xet clients reconstruct client-side instead.
	ReconstructFile(ctx context.Context, fileHash merklehash.Hash, start, end int64, w io.Writer) error
	// MissingXorbs lists the xorbs of the file this CAS does not hold
	// (yet - on a synced folder they may still be in transit). The LFS
	// bridge refuses to start a download it could not finish.
	MissingXorbs(ctx context.Context, fileHash merklehash.Hash) ([]merklehash.Hash, error)
}

// Server implements the Hub API shim. CASBaseURL is the base URL of the
// paired casserver.Server instance (e.g. "http://localhost:8420"), handed
// out via the xet-token routes' X-Xet-Cas-Url header. CAS provides the
// bridge from a committed file's plain SHA-256 to its Xet/Merkle hash.
type Server struct {
	CASBaseURL string
	CAS        casInfo
	mux        *http.ServeMux

	// mu guards only the repos map itself (adding a new repoKey); each
	// repoState has its own mutex for its revisions map, and each
	// revisionState has its own mutex for its files - a commit/resolve on
	// one repo, or one revision within a repo, never blocks on unrelated
	// activity elsewhere.
	mu    sync.RWMutex
	repos map[repoKey]*repoState

	// configMu guards authenticator/minter/tokenTTL, which handlers read
	// while their setters may replace them at runtime (SetAuthenticator is
	// explicitly documented safe to call at any time).
	configMu sync.RWMutex

	// authenticator gates every route per its required scope (see
	// requireScope and each dispatch handler below). Defaults to
	// auth.NoAuth{} - this server's pre-v0.8.0 behavior, unconditionally
	// allowing every request - until SetAuthenticator is called with
	// something else.
	authenticator auth.Authenticator

	// minter issues the CAS access tokens the xet-{read,write}-token
	// routes and the git-lfs batch actions hand out. Defaults to
	// randomTokenMinter - a fresh random string per call, which only
	// auth.NoAuth accepts and which is exactly what this server issued
	// before it had a minter. cmd/xetd installs the auth.SignedTokenAuth
	// it also gave the CAS, so the tokens verify there.
	minter   auth.TokenMinter
	tokenTTL time.Duration

	// locks is where git-lfs file locks live (lockstore.go). Defaults to
	// the in-memory, snapshotted store; SetLockDir switches to files in
	// a directory for a synced-folder deployment.
	locks lockStore
}

type repoKey struct {
	repoType string
	repoID   string
}

// fileRef is one committed file's identity: its path in the repo, plain
// SHA-256 (as declared in the commit's lfsFile.oid), and the Xet/Merkle
// file hash the CAS layer indexes it under (backfilled once known).
type fileRef struct {
	Path      string
	SHA256Hex string
	XetHash   merklehash.Hash
	Size      int64
}

// defaultRevision is created implicitly for every repo on first touch,
// matching how a real repo always has a default branch even before any
// commit - the same way real HF Hub's repo creation immediately gives you
// a "main" you can push to.
const defaultRevision = "main"

// repoState holds one repo's independent revisions. mu guards only the
// revisions map itself; each revisionState guards its own files/commit
// metadata.
type repoState struct {
	mu        sync.RWMutex
	revisions map[string]*revisionState

	// locks holds this repo's git-lfs file locks by lock id (see
	// lfslocks.go); locksMu guards it independently of mu, since lock
	// traffic never needs the revisions map.
	locksMu sync.Mutex
	locks   map[string]*lfsLock
}

// revisionState is one revision's (branch's) committed file set and
// commit history within a repo - what used to be repoState's fields
// directly, before repos gained more than one revision.
type revisionState struct {
	mu         sync.RWMutex
	files      map[string]*fileRef // keyed by path in repo
	commitOID  string
	commitSeen bool
}

func New(casBaseURL string, cas casInfo) *Server {
	s := &Server{
		CASBaseURL:    casBaseURL,
		CAS:           cas,
		mux:           http.NewServeMux(),
		repos:         make(map[repoKey]*repoState),
		authenticator: auth.NoAuth{},
		minter:        randomTokenMinter{},
		tokenTTL:      defaultTokenTTL,
	}
	s.locks = memoryLockStore{s}
	s.routes()
	return s
}

// SetLockDir stores git-lfs locks as write-once files under dir instead
// of in memory, so several replicas sharing a synced folder agree on
// who holds what (see lockstore.go). Call before serving.
func (s *Server) SetLockDir(dir string) error {
	store, err := newFolderLockStore(dir)
	if err != nil {
		return err
	}
	s.locks = store
	return nil
}

// defaultTokenTTL is how long a minted CAS token stays valid - long
// enough that a single git push of a multi-GB file rarely needs the
// refresh route, short enough that a leaked token from a log is not a
// standing credential.
const defaultTokenTTL = time.Hour

// SetTokenMinter replaces the minter behind the xet-{read,write}-token
// routes and the git-lfs batch actions. Pass the same auth.SignedTokenAuth
// the paired CAS authenticates with, so tokens this server issues are
// accepted there.
func (s *Server) SetTokenMinter(m auth.TokenMinter) {
	if m != nil {
		s.configMu.Lock()
		s.minter = m
		s.configMu.Unlock()
	}
}

// SetTokenTTL sets the lifetime of minted tokens (default one hour).
// Non-positive values are ignored.
func (s *Server) SetTokenTTL(ttl time.Duration) {
	if ttl > 0 {
		s.configMu.Lock()
		s.tokenTTL = ttl
		s.configMu.Unlock()
	}
}

// SetAuthenticator replaces this server's Authenticator (default
// auth.NoAuth{}, i.e. no enforcement - this server's pre-v0.8.0
// behavior). Safe to call at any time - unlike casserver's
// SetAuthenticator, hubserver's routes dispatch by parsing the path
// inside each handler rather than registering one mux pattern per
// logical endpoint, so there's no route table to rebuild.
func (s *Server) SetAuthenticator(a auth.Authenticator) {
	s.configMu.Lock()
	s.authenticator = a
	s.configMu.Unlock()
}

func (s *Server) authenticatorSnapshot() auth.Authenticator {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.authenticator
}

func (s *Server) minterSnapshot() (auth.TokenMinter, time.Duration) {
	s.configMu.RLock()
	defer s.configMu.RUnlock()
	return s.minter, s.tokenTTL
}

// requireScope authenticates r against s.authenticator and checks for
// scope, writing a 401 (no/invalid credential) or 403 (valid credential,
// insufficient scope) and returning false if the request should not
// proceed. Mirrors casserver.Server.requireScope's semantics exactly
// (see its doc comment) - kept as a plain bool-returning helper instead
// of a http.HandlerFunc-wrapping middleware here, since hubserver's
// dispatch handlers (handleAPIGet/handleAPIPost/handleResolveDispatch)
// need to parse the path before they know which scope applies, unlike
// casserver's one-mux-pattern-per-endpoint routing.
func (s *Server) requireScope(w http.ResponseWriter, r *http.Request, scope auth.Scope) bool {
	_, ok := s.authenticate(w, r, scope)
	return ok
}

// requireRepoScope authenticates r and additionally requires that the
// credential may act on repo. A minted token carries its repo in the
// MACed payload, so a token for alice/one presented on a bob/two route is
// rejected here with 403; the shared secret, no-auth, and any custom
// Authenticator principal not implementing auth.RepoScopedPrincipal remain
// unrestricted (see auth.AllowsRepo).
func (s *Server) requireRepoScope(w http.ResponseWriter, r *http.Request, scope auth.Scope, repo auth.Repo) (auth.Principal, bool) {
	principal, ok := s.authenticate(w, r, scope)
	if !ok {
		return nil, false
	}
	if !auth.AllowsRepo(principal, repo) {
		httpErrorJSON(w, "credential is not scoped to repository "+repo.String(), http.StatusForbidden)
		return nil, false
	}
	return principal, true
}

// authenticate is requireScope returning the Principal too, for the
// routes that need to know WHO passed (the token routes bind the minted
// token to the caller's subject; git-lfs locks record it as the owner).
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, scope auth.Scope) (auth.Principal, bool) {
	principal, err := s.authenticatorSnapshot().Authenticate(r)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			httpErrorJSON(w, "unauthenticated: "+err.Error(), http.StatusUnauthorized)
		} else {
			httpErrorJSON(w, "authentication failed: "+err.Error(), http.StatusForbidden)
		}
		return nil, false
	}
	if !principal.HasScope(scope) {
		httpErrorJSON(w, "principal lacks required scope: "+string(scope), http.StatusForbidden)
		return nil, false
	}
	return principal, true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) routes() {
	// repos/create is dispatched through handleAPIPost (which checks
	// rest == "repos/create"), NOT registered as its own literal mux
	// pattern here - Go's ServeMux prefers a more specific literal pattern
	// over a wildcard one, so a direct "POST /api/repos/create" route
	// would take priority over "POST /api/{rest...}" below and bypass
	// handleAPIPost's requireScope check on this endpoint entirely.
	//
	// repoID in real Hub URLs is "namespace/name" (contains a slash), so
	// these routes take the whole remainder as one wildcard and parse the
	// repo type / repo ID / trailing segment out of it manually.
	//
	// No routing.MountWithVersion here - huggingface_hub's real REST API
	// is unversioned (no "/v1" segment exists in the actual protocol this
	// mirrors), so routing.Mount (no version prefix) is used instead,
	// still getting the same declarative-route-table shape as
	// casserver/internal/api.
	routing.Apply(s.mux, []routing.Route{
		routing.Mount("GET", "/api/{rest...}", http.HandlerFunc(s.handleAPIGet)),
		routing.Mount("POST", "/api/{rest...}", http.HandlerFunc(s.handleAPIPost)),
		// A single handler (registered for both methods on the same
		// pattern, rather than separate HEAD/GET registrations) avoids
		// Go's ServeMux treating "HEAD /{rest...}" as ambiguous against
		// "GET /api/{rest...}" (HEAD implicitly falls back to a GET
		// pattern's handler otherwise).
		routing.Mount("", "/{rest...}", http.HandlerFunc(s.handleResolveDispatch)),
	})
}

// splitRepoPath splits a path of the form
// "{repoType}s/{namespace}/{name}/{tail...}" into repoType, "{namespace}/{name}",
// and the remaining tail segments. repoType is singularized ("models" ->
// "model") to match huggingface_hub's repo_type values.
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

// handleAPIGet dispatches GET /api/... requests: xet-{read,write}-token,
// revision (repo info), and tree (file listing) routes, keyed by repo
// type/ID and matched by the tail segments' first element.
func (s *Server) handleAPIGet(w http.ResponseWriter, r *http.Request) {
	repoType, repoID, tail, ok := splitRepoPath(r.PathValue("rest"))
	if !ok || len(tail) < 2 {
		http.NotFound(w, r)
		return
	}
	repo := auth.Repo{Type: repoType, ID: repoID}
	switch tail[0] {
	case "xet-read-token":
		principal, ok := s.requireRepoScope(w, r, auth.ScopeRead, repo)
		if !ok {
			return
		}
		s.handleXetToken(w, r, repoType, repoID, auth.ScopeRead, principal.Subject())
	case "xet-write-token":
		principal, ok := s.requireRepoScope(w, r, auth.ScopeWrite, repo)
		if !ok {
			return
		}
		s.handleXetToken(w, r, repoType, repoID, auth.ScopeWrite, principal.Subject())
	case "revision":
		if _, ok := s.requireRepoScope(w, r, auth.ScopeRead, repo); !ok {
			return
		}
		s.handleRepoInfo(w, r, repoType, repoID, tail[1])
	case "tree":
		if _, ok := s.requireRepoScope(w, r, auth.ScopeRead, repo); !ok {
			return
		}
		// tail[2:] is the optional path-in-repo, itself a single
		// (percent-decoded-by-net/http) path segment - see
		// list_repo_tree's encoded_path_in_repo, which quotes it with
		// safe="" so a "/" inside it is percent-encoded rather than
		// splitting into more segments.
		var pathInRepo string
		if len(tail) > 2 {
			pathInRepo = strings.Join(tail[2:], "/")
		}
		s.handleListTree(w, r, repoType, repoID, tail[1], pathInRepo)
	default:
		http.NotFound(w, r)
	}
}

// handleAPIPost dispatches POST /api/... requests: repo creation, preupload
// mode negotiation, and commit - keyed the same way as handleAPIGet.
func (s *Server) handleAPIPost(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	if rest == "repos/create" {
		principal, ok := s.authenticate(w, r, auth.ScopeWrite)
		if !ok {
			return
		}
		s.handleCreateRepo(w, r, principal)
		return
	}
	repoType, repoID, tail, ok := splitRepoPath(rest)
	if !ok || len(tail) < 2 {
		http.NotFound(w, r)
		return
	}
	repo := auth.Repo{Type: repoType, ID: repoID}
	revision := tail[1]
	switch tail[0] {
	case "commit":
		if _, ok := s.requireRepoScope(w, r, auth.ScopeWrite, repo); !ok {
			return
		}
		s.handleCommit(w, r, repoType, repoID, revision)
	case "preupload":
		if _, ok := s.requireRepoScope(w, r, auth.ScopeWrite, repo); !ok {
			return
		}
		s.handlePreupload(w, r)
	case "branch":
		if _, ok := s.requireRepoScope(w, r, auth.ScopeWrite, repo); !ok {
			return
		}
		// tail[1] here is the branch name being created, not a revision to
		// operate against - handleCreateBranch's own signature names it
		// accordingly.
		s.handleCreateBranch(w, r, repoType, repoID, revision)
	default:
		http.NotFound(w, r)
	}
}

// handleResolveDispatch dispatches GET/HEAD resolve requests and the
// git-lfs batch endpoint. Unlike the /api/ routes, resolve URLs have no
// leading /api/ segment. Three on-wire shapes are known:
//   - models:              "{namespace}/{name}/resolve/{revision}/{filename...}"
//   - datasets / spaces:   "{repo_type}s/{namespace}/{name}/resolve/{revision}/{filename...}"
//   - future repo types:   any leading segment(s) before "{namespace}/{name}"
//
// The git-lfs batch path parallels this: "{repo_id}.git/info/lfs/objects/batch"
// with the same optional leading repo-type prefix. Rather than
// hard-coding today's prefix set (datasets/spaces/buckets/...), parse
// from the RIGHT: find "/resolve/" (or the ".git/info/lfs/objects/batch"
// suffix) and take the two segments IMMEDIATELY before it as
// namespace/name. That way any current or future repo-type prefix a real
// Hub URL might carry is transparently accepted without a code change
// per type.
func (s *Server) handleResolveDispatch(w http.ResponseWriter, r *http.Request) {
	rest := r.PathValue("rest")
	if strings.Contains(rest, lfsPathMarker) {
		s.handleLFS(w, r, rest)
		return
	}
	repoType, repoID, revision, filename, ok := parseResolvePath(rest)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, ok := s.requireRepoScope(w, r, auth.ScopeRead, auth.Repo{Type: repoType, ID: repoID}); !ok {
		return
	}
	s.handleResolve(w, r, repoType, repoID, revision, filename)
}

// parseResolvePath finds the "/resolve/" marker in rest and returns the
// two path segments IMMEDIATELY before it as repoID (namespace/name),
// with the revision and filename taken from AFTER the marker, and
// repoType derived from whatever segment precedes the namespace
// ("datasets" -> "dataset", "spaces" -> "space", nothing -> "model").
// Parsing from the right means any future repo-type prefix a real Hub URL
// adds is accepted without a code change here.
func parseResolvePath(rest string) (repoType, repoID, revision, filename string, ok bool) {
	const marker = "/resolve/"
	idx := strings.Index(rest, marker)
	if idx < 0 {
		return "", "", "", "", false
	}
	// Head: everything before "/resolve/", i.e. "[type/...]owner/name".
	// Take the last two segments as the repo ID, and whatever precedes
	// them as the repo-type prefix.
	headParts := strings.Split(rest[:idx], "/")
	if len(headParts) < 2 {
		return "", "", "", "", false
	}
	// Both repo-ID segments must be non-empty. Without this, a path like
	// "//resolve//0" parses as repoID "/" with an empty namespace AND an
	// empty name - a repo identity no real request can address, which
	// would then be created as live state and could be collided with by
	// any other equally-malformed path. (Found by FuzzParseResolvePath.)
	namespace, name := headParts[len(headParts)-2], headParts[len(headParts)-1]
	if namespace == "" || name == "" {
		return "", "", "", "", false
	}
	repoID = namespace + "/" + name
	repoType = repoTypeFromPrefix(headParts[:len(headParts)-2])
	// Tail: "{revision}/{filename...}"
	tail := rest[idx+len(marker):]
	slash := strings.Index(tail, "/")
	if slash < 0 {
		return "", "", "", "", false
	}
	revision = tail[:slash]
	filename = tail[slash+1:]
	// An empty revision is as meaningless as an empty repo segment, and
	// would otherwise be looked up as a revision literally named "".
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

// extractRepoIDBefore returns the two segments IMMEDIATELY before suffix
// (matching parseResolvePath's owner/name extraction). Any leading
// repo-type segment(s) are dropped, mirroring parseResolvePath's rules.
// Used by the LFS-batch dispatch to accept dataset/space/etc.-prefixed
// batch URLs the same way it accepts model-shaped ones.
func extractRepoIDBefore(rest, suffix string) string {
	head := strings.TrimSuffix(rest, suffix)
	parts := strings.Split(head, "/")
	if len(parts) < 2 {
		return head
	}
	return parts[len(parts)-2] + "/" + parts[len(parts)-1]
}

// getOrCreateRepo returns the repoState for repoType/repoID, creating it
// (with an implicit "main" revision already present) on first touch.
func (s *Server) getOrCreateRepo(repoType, repoID string) *repoState {
	key := repoKey{repoType: repoType, repoID: repoID}
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, ok := s.repos[key]
	if !ok {
		rs = &repoState{
			revisions: map[string]*revisionState{defaultRevision: newRevisionState()},
			locks:     make(map[string]*lfsLock),
		}
		s.repos[key] = rs
	}
	return rs
}

func newRevisionState() *revisionState {
	return &revisionState{files: make(map[string]*fileRef)}
}

// getOrCreateRevision returns rs's revisionState for the named revision,
// creating an empty one on first touch - matching how pushing to a new
// branch name on a real repo implicitly creates that branch. An empty
// revision string is treated as defaultRevision, since some call sites
// (e.g. a resolve URL with no revision segment) may not always supply one
// explicitly.
func (rs *repoState) getOrCreateRevision(revision string) *revisionState {
	if revision == "" {
		revision = defaultRevision
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	v, ok := rs.revisions[revision]
	if !ok {
		v = newRevisionState()
		rs.revisions[revision] = v
	}
	return v
}

// getRevision returns rs's revisionState for the named revision without
// creating it, or false if that revision doesn't exist yet - used by
// read paths (resolve) where a nonexistent revision should 404, not
// silently spring into existence.
func (rs *repoState) getRevision(revision string) (*revisionState, bool) {
	if revision == "" {
		revision = defaultRevision
	}
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	v, ok := rs.revisions[revision]
	return v, ok
}

// httpErrorJSON writes a JSON error response and logs it at a level
// matching its cause - see casserver.httpError's comment for why 5xx and
// 4xx are split between Warn and Debug.
func httpErrorJSON(w http.ResponseWriter, msg string, code int) {
	if code >= 500 {
		slog.Warn("hubserver: request failed", "status", code, "error", msg)
	} else {
		slog.Debug("hubserver: request rejected", "status", code, "error", msg)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
