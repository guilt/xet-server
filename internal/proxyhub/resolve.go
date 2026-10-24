package proxyhub

// resolve.go implements the cached read path for HEAD (and, minimally,
// GET) /{repo_id}/resolve/{revision}/{filename}, serving from Embedded
// (a real *hubserver.Server) once the file is known and fresh -
// matching internal/hubserver's own handleResolve byte-for-byte,
// including its X-Xet-Refresh-Route header: Embedded's own
// refreshRouteURL already builds that from the incoming request's own
// Host, which is already this proxy's own address, not the real Hub's -
// so no rewrite step is needed here at all.

import (
	"net/http"
	"strconv"

	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/hfclient"
)

// handleResolve serves one file's resolve metadata. repoType comes from
// the request URL's own prefix (see parseResolvePath): "model" for a bare
// /{repo_id}/resolve/... path, "dataset"/"space" for the prefixed shapes.
// It is threaded into BOTH the upstream call (the real Hub 404s a dataset
// resolved at the model URL) and every Embedded Ingest*/Has* call, which
// key their state by repoType - mixing types there would look up the
// wrong revisionState.
func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request, repoType, repoID, revision, filename string) {
	key := cacheKey(repoType, repoID, revision, filename, credentialFingerprint(r))
	cred := auth.CredentialFromRequest(r)

	if s.NoCache {
		info, err := s.Hub.Resolve(r.Context(), cred, repoType, repoID, revision, filename)
		if err != nil {
			writeUpstreamError(w, err)
			return
		}
		if info.XetHash == "" {
			s.relayHubLive(w, r)
			return
		}
		writeResolveHeaders(w, r, repoType, repoID, revision, info)
		return
	}

	if s.resolveFreshness.Fresh(key, s.CacheTTL) && s.Embedded.HasFile(repoType, repoID, revision, filename) {
		s.Embedded.ServeHTTP(w, r)
		return
	}

	callCtx, cancel := s.callContext(r)
	info, err := s.Hub.Resolve(callCtx, cred, repoType, repoID, revision, filename)
	cancel()
	if err != nil {
		// Only this credential's own prior successful fetch may back a
		// stale serve - see handleRepoInfo's identical note.
		if !isAuthFailure(err) && s.Embedded.HasFile(repoType, repoID, revision, filename) {
			s.Embedded.ServeHTTP(w, r)
			return
		}
		writeUpstreamError(w, err)
		return
	}

	// A file with no X-Xet-Hash upstream is NOT a Xet file (e.g. a small
	// inline blob like a repo's README.md or .gitattributes). Embedded's
	// resolve handler can only serve Xet files - it answers via the CAS
	// reconstruction data keyed by the Xet hash, and this proxy's
	// XetHashForSHA256 bridge reports "unknown" for everything else - so
	// serving from Embedded would 404 (exactly the bigcode/the-stack-v2
	// failure on resolve/main/.gitattributes after the directory fix).
	// These files are tiny metadata blobs; relay them live from the real
	// Hub instead, and never ingest them into Embedded (so the cached
	// path above can't later hand back a CAS-backed 404). Real Xet files
	// keep the fetch-and-cache path below.
	if info.XetHash == "" {
		s.relayHubLive(w, r)
		return
	}

	xetHash := parseXetHashHex(info.XetHash)
	s.recordFileSize(xetHash, info.LinkedSize)
	s.Embedded.IngestFile(repoType, repoID, revision, filename, trimQuotes(info.ETag), info.LinkedSize, xetHash)
	if info.RepoCommit != "" {
		s.Embedded.IngestCommit(repoType, repoID, revision, info.RepoCommit)
	}
	s.resolveFreshness.MarkFresh(key)
	s.Embedded.ServeHTTP(w, r)
}

// writeResolveHeaders is the -no-cache path's own header writer,
// matching hubserver's exact header set without needing Embedded at
// all - mirrors internal/hubserver/resolve.go's handleResolve.
func writeResolveHeaders(w http.ResponseWriter, r *http.Request, repoType, repoID, revision string, info *hfclient.ResolveInfo) {
	refreshRoute := refreshRouteURL(r, repoType, repoID, revision)
	w.Header().Set("X-Repo-Commit", info.RepoCommit)
	w.Header().Set("ETag", info.ETag)
	w.Header().Set("X-Linked-Etag", info.ETag)
	w.Header().Set("X-Linked-Size", strconv.FormatInt(info.LinkedSize, 10))
	w.Header().Set("Content-Length", strconv.FormatInt(info.LinkedSize, 10))
	w.Header().Set("X-Xet-Hash", info.XetHash)
	w.Header().Set("X-Xet-Refresh-Route", refreshRoute)

	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Error(w, "direct GET not supported; use the Xet download path via X-Xet-Hash", http.StatusNotImplemented)
}

// refreshRouteURL is proxyhub's own copy of hubserver.refreshRouteURL -
// duplicated (not imported) since it's an unexported helper of a
// package this one only otherwise touches through its exported
// Ingest*/Has*/ServeHTTP surface (see splitRepoPath's identical note in
// proxyhub.go). Encodes the X-Xet-Refresh-Route wire contract, so any
// change here must be mirrored in hubserver's copy.
//
// The /api/ namespace always carries a pluralized repo type, so a
// dataset's refresh route must be /api/datasets/... - hardcoding
// "models" here would send the client's token refresh to a nonexistent
// model of the same name once its first token expired mid-download.
func refreshRouteURL(r *http.Request, repoType, repoID, revision string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/api/" + repoType + "s/" + repoID + "/xet-read-token/" + revision
}
