package proxyhub

// tree.go implements the cached read path for GET
// /api/{repo_type}s/{repo_id}/tree/{revision}[/{path_in_repo}], serving
// from Embedded (a real *hubserver.Server) once the revision's full
// file list is known and fresh - matching internal/hubserver's own
// handleListTree byte-for-byte, since it's the same code.

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/hfclient"
	"github.com/guilt/xet-server/internal/merklehash"
)

// handleListTree implements the endpoint described above.
func (s *Server) handleListTree(w http.ResponseWriter, r *http.Request, repoType, repoID, revision, pathInRepo string) {
	key := cacheKey(repoType, repoID, revision, credentialFingerprint(r))
	cred := auth.CredentialFromRequest(r)

	if s.NoCache {
		entries, err := s.Hub.ListTree(r.Context(), cred, repoType, repoID, revision)
		if err != nil {
			writeUpstreamError(w, err)
			return
		}
		writeTreeJSON(w, entries, pathInRepo)
		return
	}

	if s.treeFreshness.Fresh(key, s.CacheTTL) && s.Embedded.HasRevision(repoType, repoID, revision) {
		s.Embedded.ServeHTTP(w, r)
		return
	}

	entries, err := s.Hub.ListTree(r.Context(), cred, repoType, repoID, revision)
	if err != nil {
		// Only this credential's own prior successful fetch may back a
		// stale serve - see handleRepoInfo's identical note.
		if !isAuthFailure(err) && s.Embedded.HasRevision(repoType, repoID, revision) {
			s.Embedded.ServeHTTP(w, r)
			return
		}
		writeUpstreamError(w, err)
		return
	}

	s.Embedded.IngestRepoInfo(repoType, repoID, revision)
	for _, e := range entries {
		// The upstream tree interleaves real files with directory
		// entries (type "directory", size 0, a tree OID rather than file
		// content). The embedded hubserver has no folder concept - every
		// IngestFile records ends up served as "type": "file" (see
		// internal/hubserver/tree.go), so recording a directory here
		// would make huggingface_hub's snapshot_download build a
		// RepoFile for it and try to resolve it, which 404s - exactly
		// the bigcode/the-stack-v2 failure (top-level "data" folder).
		if e.Type != "file" {
			continue
		}
		xetHash := parseXetHashHex(e.XetHash)
		s.recordFileSize(xetHash, e.Size)
		s.Embedded.IngestFile(repoType, repoID, revision, e.Path, e.OID, e.Size, xetHash)
	}
	s.treeFreshness.MarkFresh(key)
	s.Embedded.ServeHTTP(w, r)
}

// writeTreeJSON is the -no-cache path's own response writer, matching
// hubserver's exact wire shape (a bare JSON array - see
// internal/hubserver/tree.go's doc comment on why) without needing
// Embedded at all. Non-file entries (directories) are filtered out so the
// -no-cache path can never hand a client a directory masquerading as a
// file either.
func writeTreeJSON(w http.ResponseWriter, entries []hfclient.TreeEntry, pathInRepo string) {
	filtered := make([]hfclient.TreeEntry, 0, len(entries))
	for _, e := range entries {
		if e.Type != "file" {
			continue
		}
		if pathInRepo != "" && !isUnderPath(e.Path, pathInRepo) {
			continue
		}
		filtered = append(filtered, e)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(filtered); err != nil {
		slog.Error("proxyhub: encode response", "error", err)
	}
}

// parseXetHashHex parses hex (a tree entry's optional XetHash field) into
// a merklehash.Hash, or the zero Hash if hex is empty or malformed -
// this is a best-effort enrichment (letting a subsequent local resolve
// skip its own CAS lookup), never a hard failure: a tree listing without
// this field is still perfectly usable.
func parseXetHashHex(hex string) merklehash.Hash {
	if hex == "" {
		return merklehash.Hash{}
	}
	h, err := merklehash.FromHex(hex)
	if err != nil {
		return merklehash.Hash{}
	}
	return h
}

// isUnderPath is proxyhub's own copy of hubserver.isUnderPath -
// duplicated (not imported) for the same reason as splitRepoPath (see
// its note in proxyhub.go): an unexported helper of a package this one
// only otherwise touches through its exported surface.
func isUnderPath(path, pathInRepo string) bool {
	if path == pathInRepo {
		return true
	}
	return len(path) > len(pathInRepo) && path[:len(pathInRepo)] == pathInRepo && path[len(pathInRepo)] == '/'
}
