package hubserver

// lfs.go: the git-lfs face of this server. Setting `lfs.url` in a git
// repo's .lfsconfig to
//
//	http://<hub-host>/{owner}/{name}.git/info/lfs
//
// makes the stock git-lfs client send every batch, object, and lock
// request here while the git objects themselves go to any plain git
// host. The endpoints under that prefix:
//
//	POST objects/batch            - negotiate transfers (lfsbatch.go):
//	                                uploads are answered with the "xet"
//	                                transfer for git-xet, downloads with
//	                                "basic" hrefs served by ...
//	GET  objects/{oid}            - ... this: whole-file (or Range) bytes
//	                                reconstructed from xorbs (lfsobjects.go)
//	POST locks, GET locks,
//	POST locks/verify,
//	POST locks/{id}/unlock        - the git-lfs File Locking API (lfslocks.go)
//
// Everything here answers with the git-lfs media type and the {"message"}
// error body git-lfs shows to users, and a 401 carries LFS-Authenticate so
// git-lfs knows to ask git's credential helper and retry with Basic auth.

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/guilt/xet-server/internal/auth"
)

// lfsMediaType is the content type git-lfs sends and expects.
const lfsMediaType = "application/vnd.git-lfs+json"

// lfsPathMarker is what makes a request path an LFS request: the
// ".git/info/lfs" git-lfs appends to the repo URL. Everything before it
// names the repo (with any repo-type prefix, like resolve URLs), and
// everything after it is the LFS endpoint.
const lfsPathMarker = ".git/info/lfs"

// lfsBatchPathSuffix is kept for extractRepoIDBefore's fuzz coverage: the
// full batch-endpoint suffix as it appears at the end of a batch URL.
const lfsBatchPathSuffix = "/info/lfs/objects/batch"

// splitLFSPath parses "[type/]{owner}/{name}.git/info/lfs[/{endpoint}]"
// into repoType ("model" for the unprefixed form), repoID ("owner/name"),
// and the endpoint after the marker (no leading slash; "" for a bare
// lfs.url). ok is false when the two segments before ".git" are not a
// usable owner/name.
func splitLFSPath(rest string) (repoType, repoID, endpoint string, ok bool) {
	idx := strings.Index(rest, lfsPathMarker)
	if idx < 0 {
		return "", "", "", false
	}
	head := rest[:idx]
	parts := strings.Split(head, "/")
	if len(parts) < 2 {
		return "", "", "", false
	}
	owner, name := parts[len(parts)-2], parts[len(parts)-1]
	if owner == "" || name == "" {
		return "", "", "", false
	}
	repoType = repoTypeFromPrefix(parts[:len(parts)-2])
	endpoint = strings.TrimPrefix(rest[idx+len(lfsPathMarker):], "/")
	return repoType, owner + "/" + name, endpoint, true
}

// handleLFS dispatches every request whose path carries lfsPathMarker.
func (s *Server) handleLFS(w http.ResponseWriter, r *http.Request, rest string) {
	repoType, repoID, endpoint, ok := splitLFSPath(rest)
	if !ok {
		lfsError(w, "malformed repo id in LFS URL: want {owner}/{name}.git/info/lfs", http.StatusBadRequest)
		return
	}
	repo := auth.Repo{Type: repoType, ID: repoID}
	switch {
	case endpoint == "objects/batch":
		s.handleLFSBatch(w, r, repo)
	case strings.HasPrefix(endpoint, "objects/"):
		oid := strings.TrimPrefix(endpoint, "objects/")
		s.handleLFSObject(w, r, repo, oid)
	case endpoint == "locks":
		s.handleLFSLocks(w, r, repo)
	case endpoint == "locks/verify":
		s.handleLFSLocksVerify(w, r, repo)
	case strings.HasPrefix(endpoint, "locks/") && strings.HasSuffix(endpoint, "/unlock"):
		id := strings.TrimSuffix(strings.TrimPrefix(endpoint, "locks/"), "/unlock")
		s.handleLFSUnlock(w, r, repo, id)
	default:
		lfsError(w, "unknown LFS endpoint", http.StatusNotFound)
	}
}

// lfsErrorBody is the error shape every git-lfs API endpoint shares.
type lfsErrorBody struct {
	Message string `json:"message"`
}

// lfsError writes a git-lfs style error. A 401 also carries
// LFS-Authenticate, which is what tells git-lfs to obtain a credential
// (via git-credential) and retry the request with HTTP Basic auth.
func lfsError(w http.ResponseWriter, msg string, code int) {
	if code >= 500 {
		slog.Warn("hubserver: lfs request failed", "status", code, "error", msg)
	} else {
		slog.Debug("hubserver: lfs request rejected", "status", code, "error", msg)
	}
	if code == http.StatusUnauthorized {
		w.Header().Set("LFS-Authenticate", `Basic realm="xet-server"`)
	}
	writeLFSJSON(w, code, lfsErrorBody{Message: msg})
}

func writeLFSJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", lfsMediaType)
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("hubserver: encode lfs response", "error", err)
	}
}

// lfsAuthenticate is authenticate with git-lfs shaped failures: the same
// 401/403 split, but a {"message"} body and an LFS-Authenticate challenge.
func (s *Server) lfsAuthenticate(w http.ResponseWriter, r *http.Request, scope auth.Scope, repo auth.Repo) (auth.Principal, bool) {
	principal, err := s.authenticator.Authenticate(r)
	if err != nil {
		if errors.Is(err, auth.ErrUnauthenticated) {
			lfsError(w, "authentication required: "+err.Error(), http.StatusUnauthorized)
		} else {
			lfsError(w, "authentication failed: "+err.Error(), http.StatusForbidden)
		}
		return nil, false
	}
	if !principal.HasScope(scope) {
		lfsError(w, "credential lacks "+string(scope)+" access to this repository", http.StatusForbidden)
		return nil, false
	}
	if !auth.AllowsRepo(principal, repo) {
		lfsError(w, "credential is not scoped to repository "+repo.String(), http.StatusForbidden)
		return nil, false
	}
	return principal, true
}

// lfsBaseURL is the scheme://host this request arrived on, used to build
// absolute hrefs in batch responses. Honors X-Forwarded-Proto so a TLS
// reverse proxy in front of a plain-HTTP xetd yields https hrefs.
func lfsBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd == "https" || fwd == "http" {
		scheme = fwd
	}
	return scheme + "://" + r.Host
}

// isLFSOID reports whether oid is a lowercase 64-hex SHA-256, the only
// object id git-lfs produces.
func isLFSOID(oid string) bool {
	if len(oid) != 64 {
		return false
	}
	for _, c := range oid {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
