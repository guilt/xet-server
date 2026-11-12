// ingest.go defines the API a caller embedding this Server as a caching
// layer (internal/proxyhub, wrapping this server instead of rebuilding
// its repoState/revisionState model independently) uses to record a
// repo/revision/file it learned about from an upstream Hub response,
// exactly as if a real client had committed it through the normal write
// path (handleCommit/handleCreateBranch) - so a caching proxy sitting in
// front of the real huggingface.co and this Server end up with identical
// state for anything the proxy has touched, and a plain xetd pointed at
// the same -data directory afterward serves it with zero migration step.
// See internal/casserver's own IngestXorb/IngestShard for the CAS-side
// counterpart to this pattern.
package hubserver

import "github.com/guilt/xet-server/internal/merklehash"

// IngestRepoInfo ensures repoType/repoID/revision exist locally - the
// same side effect handleRepoInfo's own repo/revision lookups already
// have (getOrCreateRepo always creates on first touch; a revision is
// only created here, not looked up, so this always leaves it present
// afterward, unlike handleRepoInfo's read-only getRevision check). A
// caller that only learned "this repo/revision exists" from an upstream
// repo-info response - with no actual file contents yet - uses this
// alone; IngestFile (below) is for when file contents are also known.
func (s *Server) IngestRepoInfo(repoType, repoID, revision string) {
	rs := s.getOrCreateRepo(repoType, repoID)
	rs.getOrCreateRevision(revision)
}

// IngestFile records path's existence and metadata within
// repoType/repoID/revision as if it had been committed - for a caller
// that learned about it from an upstream tree-listing or resolve
// response rather than a real commit ndjson payload. xetHash may be the
// zero Hash if not yet known (matching a freshly-committed file before
// resolve.go's lazy CAS backfill runs - see fileRef's own doc comment);
// callers that do already know it (e.g. a tree-listing response's
// xetHash field, or a resolve response's X-Xet-Hash header) should pass
// it so a subsequent local resolve doesn't need its own CAS lookup.
func (s *Server) IngestFile(repoType, repoID, revision, path, sha256Hex string, size int64, xetHash merklehash.Hash) {
	rs := s.getOrCreateRepo(repoType, repoID)
	vs := rs.getOrCreateRevision(revision)
	vs.mu.Lock()
	// Repo-info's sibling list and tree listings can both arrive without a
	// per-file Xet hash (or with size 0). Both are useful for existence/
	// listing, but neither may clobber richer resolve/tree metadata already
	// learned for the same path: a concurrent upstream repo-info response
	// used to overwrite a real XetHash with zero, after which the fast-path
	// resolve 404'd until the next live resolve repaired it. Merge the
	// missing fields instead of replacing them.
	if existing, ok := vs.files[path]; ok {
		if sha256Hex == "" {
			sha256Hex = existing.SHA256Hex
		}
		if size == 0 {
			size = existing.Size
		}
		if xetHash.IsZero() {
			xetHash = existing.XetHash
		}
	}
	vs.files[path] = &fileRef{Path: path, SHA256Hex: sha256Hex, Size: size, XetHash: xetHash}
	vs.mu.Unlock()
}

// IngestCommit records commitOID as repoType/repoID/revision's current
// commit - for a caller that relayed a real commit write-through to the
// real Hub (which mints the actual commitOID) rather than generating one
// itself. Using the REAL upstream commit OID here, instead of this
// server's own randomCommitOID generator (see commit.go's
// handleCommit), matters: a fabricated OID unrelated to the real repo's
// actual history would make X-Repo-Commit lie about what was actually
// committed upstream.
func (s *Server) IngestCommit(repoType, repoID, revision, commitOID string) {
	rs := s.getOrCreateRepo(repoType, repoID)
	vs := rs.getOrCreateRevision(revision)
	vs.mu.Lock()
	vs.commitOID = commitOID
	vs.commitSeen = true
	vs.mu.Unlock()
}

// HasRepo reports whether repoType/repoID has been touched locally
// (created, even with no revisions committed to beyond the implicit
// default). Unlike HasRevision/HasFile, no caller embedding this Server
// currently branches on this in production - proxyhub decides whether a
// request can be served locally via HasRevision/HasFile directly, since
// those already imply the repo exists. Exported for test/diagnostic
// observability (see ingest_test.go and proxyhub_test.go).
func (s *Server) HasRepo(repoType, repoID string) bool {
	key := repoKey{repoType: repoType, repoID: repoID}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.repos[key]
	return ok
}

// HasRevision reports whether repoType/repoID has revision locally,
// without creating it (unlike getOrCreateRevision's own read side,
// getRevision, this is exported and does not require the caller to
// already hold a *repoState).
func (s *Server) HasRevision(repoType, repoID, revision string) bool {
	key := repoKey{repoType: repoType, repoID: repoID}
	s.mu.RLock()
	rs, ok := s.repos[key]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	_, ok = rs.getRevision(revision)
	return ok
}

// HasFile reports whether path has been recorded (via a real commit or
// IngestFile) under repoType/repoID/revision.
func (s *Server) HasFile(repoType, repoID, revision, path string) bool {
	key := repoKey{repoType: repoType, repoID: repoID}
	s.mu.RLock()
	rs, ok := s.repos[key]
	s.mu.RUnlock()
	if !ok {
		return false
	}
	vs, ok := rs.getRevision(revision)
	if !ok {
		return false
	}
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	_, ok = vs.files[path]
	return ok
}
