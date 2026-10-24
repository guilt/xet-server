package hubserver

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/guilt/xet-server/internal/auth"
)

type createRepoRequest struct {
	Name         string `json:"name"`
	Organization string `json:"organization"`
	Type         string `json:"type"`
}

type createRepoResponse struct {
	URL string `json:"url"`
}

// handleCreateRepo implements POST /api/repos/create: idempotently
// registers a repo (this server has no notion of "already exists" beyond
// creating the in-memory repoState on first touch, so repeat calls with
// the same name are harmless no-ops).
//
// Repo creation is the one route whose target is not already named in the
// URL, so authorization cannot compare it to the token's repo directly:
// a repo-scoped write token may create only inside its own namespace, and
// creating in a different namespace requires the shared secret's admin
// scope (see auth.AllowsRepoCreate).
func (s *Server) handleCreateRepo(w http.ResponseWriter, r *http.Request, principal auth.Principal) {
	var req createRepoRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpErrorJSON(w, "invalid request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		httpErrorJSON(w, "missing repo name", http.StatusBadRequest)
		return
	}

	repoType := req.Type
	if repoType == "" {
		repoType = "model"
	}
	repoID := req.Name
	if req.Organization != "" {
		repoID = req.Organization + "/" + req.Name
	}
	repo := auth.Repo{Type: repoType, ID: repoID}
	if !auth.AllowsRepoCreate(principal, repo) {
		httpErrorJSON(w, "credential is not allowed to create repositories outside its namespace", http.StatusForbidden)
		return
	}

	s.getOrCreateRepo(repoType, repoID)

	writeJSON(w, createRepoResponse{URL: repoID})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("hubserver: encode response", "error", err)
	}
}

// repoInfoResponse is GET /api/{repo_type}s/{repo_id}/revision/{revision}'s
// body - a small subset of the real Hub's ModelInfo/DatasetInfo/SpaceInfo
// JSON shape. huggingface_hub's snapshot_download only ever reads `sha`
// off the deserialized object (asserting it's non-nil before using it as
// the resolved commit hash for every subsequent per-file download), so
// that's the one field that must be present and meaningful; the rest are
// included because the client's dataclass constructors accept (and
// harmlessly ignore) extra fields, and because a real client inspecting
// the response for debugging should see something recognizable.
//
// sha is set to the revision name itself (e.g. "main"), not a real git
// commit hash - this shim has no separate git-commit-hash identity for a
// revision distinct from its name, and nothing in huggingface_hub
// validates sha's format; every downstream call (list_repo_tree, resolve)
// already accepts a revision name directly, so round-tripping the name
// back as "sha" keeps the whole flow internally consistent.
//
// Siblings mirrors the real Hub's per-file `siblings` array
// (huggingface_hub's ModelInfo.siblings, DatasetInfo.siblings): each entry
// is one file's path in the repo, as `{"rfilename": "<path>"}`. A
// non-empty siblings list is what lets huggingface_hub's snapshot_download
// (used by `hf download` with multiple filenames or `--include`) skip the
// separate list_repo_tree call it otherwise falls back to; that fallback
// path then feeds a generator (unknown length) into tqdm.contrib.thread_map,
// whose _min_map_len raises "min() arg is an empty sequence" when every
// iterable it's given has -1 length_hint. Populating siblings sidesteps
// that failure by turning the fallback off - snapshot_download reads
// siblings, builds a real list, and downloads happily.
type repoInfoResponse struct {
	ID       string        `json:"id"`
	SHA      string        `json:"sha"`
	Private  bool          `json:"private"`
	Siblings []repoSibling `json:"siblings"`
}

// repoSibling mirrors one element of huggingface_hub's siblings list -
// only `rfilename` is required for snapshot_download's fast path.
type repoSibling struct {
	RFilename string `json:"rfilename"`
}

// handleRepoInfo implements GET /api/{repo_type}s/{repo_id}/revision/{revision}:
// the request huggingface_hub's snapshot_download (used by `hf download`
// for a whole-repo download, as opposed to a single named file) issues
// first, to resolve revision to a commit hash before listing/downloading
// files - and the request `hf upload`'s CLI command issues first, to
// check whether the target branch already exists before creating it.
// Matches resolve.go's existing read-path convention: the repo itself is
// implicitly created on first touch (matching how a real Hub repo always
// exists once anything references it), but a nonexistent revision 404s
// with X-Error-Code: RevisionNotFound rather than being silently created
// - a repo-info lookup is a read, not a push, so it must not have the
// side effect of creating a branch nobody has committed to yet. The
// X-Error-Code header is required, not cosmetic: huggingface_hub's
// hf_raise_for_status only raises the specific RevisionNotFoundError
// (which callers like `hf upload`'s branch-creation step specifically
// catch) when this header is present; a plain 404 falls through to a
// generic, uncaught HfHubHTTPError instead.
func (s *Server) handleRepoInfo(w http.ResponseWriter, r *http.Request, repoType, repoID, revision string) {
	rs := s.getOrCreateRepo(repoType, repoID)
	vs, ok := rs.getRevision(revision)
	if !ok {
		w.Header().Set("X-Error-Code", "RevisionNotFound")
		http.NotFound(w, r)
		return
	}
	vs.mu.RLock()
	siblings := make([]repoSibling, 0, len(vs.files))
	for path := range vs.files {
		siblings = append(siblings, repoSibling{RFilename: path})
	}
	vs.mu.RUnlock()
	writeJSON(w, repoInfoResponse{ID: repoID, SHA: revision, Siblings: siblings})
}

// handleCreateBranch implements POST /api/{repo_type}s/{repo_id}/branch/{branch}:
// creates (or, matching real Hub's create_branch(exist_ok=True) contract,
// no-ops on) the named revision. Called by `hf upload`'s CLI command
// after a handleRepoInfo lookup reports the branch doesn't exist yet.
// This shim's revisions already spring into existence implicitly on
// first commit (see getOrCreateRevision) - this handler just does the
// same thing eagerly, in response to an explicit request instead of
// waiting for the first commit, so a caller that checks "does this
// branch exist" immediately afterward (e.g. via handleRepoInfo) sees it.
func (s *Server) handleCreateBranch(w http.ResponseWriter, r *http.Request, repoType, repoID, branch string) {
	rs := s.getOrCreateRepo(repoType, repoID)
	rs.getOrCreateRevision(branch)
	w.WriteHeader(http.StatusOK)
}

// xetTokenResponse is the JSON body real HF Hub returns from
// xet-{read,write}-token, per xet-core's CasJWTInfo (xet_client/src/hub_client/types.rs):
// hf_xet's Rust client decodes this response as JSON (DirectRefreshRouteTokenRefresher::get_cas_jwt),
// not from headers - a header-only response with an empty body fails
// hf_xet's resp.json() decode, which it treats as a transient error and
// retries indefinitely instead of failing fast.
type xetTokenResponse struct {
	CasURL      string `json:"casUrl"`
	Exp         int64  `json:"exp"`
	AccessToken string `json:"accessToken"`
}

// handleXetToken implements GET /api/{repo_type}s/{repo_id}/xet-{read,write}-token/{revision}:
// issues a CAS endpoint + bearer token, both as a JSON body (what hf_xet's
// Rust client actually parses) and via the X-Xet-* response headers
// (huggingface_hub's parse_xet_connection_info_from_headers, used on the
// resolve/download path). The token comes from s.minter, scoped to the
// route (read for xet-read-token, write for xet-write-token) and bound to
// the authenticated caller's subject and bound to this repo; with the
// default randomTokenMinter it is a fresh random string only a no-auth CAS
// accepts, matching this server's behavior before tokens carried any
// meaning.
func (s *Server) handleXetToken(w http.ResponseWriter, r *http.Request, repoType, repoID string, scope auth.Scope, subject string) {
	s.getOrCreateRepo(repoType, repoID)

	token, exp, err := s.mintToken(scope, subject, auth.Repo{Type: repoType, ID: repoID})
	if err != nil {
		httpErrorJSON(w, "generate token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	expiry := exp.Unix()

	w.Header().Set("X-Xet-Cas-Url", s.CASBaseURL)
	w.Header().Set("X-Xet-Access-Token", token)
	w.Header().Set("X-Xet-Token-Expiration", strconv.FormatInt(expiry, 10))
	writeJSON(w, xetTokenResponse{
		CasURL:      s.CASBaseURL,
		Exp:         expiry,
		AccessToken: token,
	})
}

// mintToken is the one place this server asks its minter for a CAS
// token, so the ttl and error handling are uniform across the token
// routes and the git-lfs batch actions.
func (s *Server) mintToken(scope auth.Scope, subject string, repo auth.Repo) (string, time.Time, error) {
	minter, ttl := s.minterSnapshot()
	return minter.MintToken(scope, subject, repo, ttl)
}

// randomTokenMinter is the default auth.TokenMinter: a random 32-hex
// string per call, carrying no verifiable meaning. Only an
// auth.NoAuth CAS accepts such a token, which is the only configuration
// in which this default is reached (cmd/xetd installs a real minter
// whenever a shared secret is configured).
type randomTokenMinter struct{}

func (randomTokenMinter) MintToken(scope auth.Scope, subject string, repo auth.Repo, ttl time.Duration) (string, time.Time, error) {
	token, err := randomToken()
	if err != nil {
		return "", time.Time{}, err
	}
	return token, time.Now().Add(ttl), nil
}

func randomToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
