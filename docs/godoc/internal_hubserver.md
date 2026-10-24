# `github.com/guilt/xet-server/internal/hubserver`

```
package hubserver // import "github.com/guilt/xet-server/internal/hubserver"

Package hubserver implements just enough of huggingface.co's Hub REST API
(distinct from the CAS API in internal/casserver) to let the real `hf upload` /
`hf download` CLI commands (via huggingface_hub) work end-to-end against a local
server, with HF_ENDPOINT pointed at it:

  - POST /api/repos/create - repo creation (idempotent)
  - GET /api/{repo_type}s/{repo_id}/xet-{read,write}-token/{revision}
  - issues a CAS endpoint + bearer token via response headers
  - POST /api/{repo_type}s/{repo_id}/commit/{revision} - ndjson commit payload
  - HEAD/GET /{repo_id}/resolve/{revision}/{filename} - file metadata + content

Each repo supports real, independent revisions (a "main" branch is created
implicitly on first touch, matching how a real repo always has a default
branch; any other revision name is created on first commit to it) -
commit/resolve/preupload all operate against the named revision's own file
set and commit history, not a single shared implicit state. No git refs/PRs
are modeled. Every route except telemetry-equivalents (there are none in
this shim) requires the scope real xet-core/Hub convention implies (write
for token/commit/preupload/repo-create, read for resolve), enforced via
auth.Authenticator - see SetAuthenticator. The default (auth.NoAuth{}) enforces
nothing, this server's behavior prior to v0.8.0: any bearer token (or none)
is accepted. State is held in memory alongside the paired casserver.Server,
since a commit's file entries need to reference the Xet file hash the CAS layer
already knows how to reconstruct - and periodically checkpointed to disk (see
Server.Snapshot/LoadSnapshot in snapshot.go) so it survives a restart.

ingest.go defines the API a caller embedding this Server as a caching
layer (internal/proxyhub, wrapping this server instead of rebuilding its
repoState/revisionState model independently) uses to record a repo/revision/file
it learned about from an upstream Hub response, exactly as if a real client had
committed it through the normal write path (handleCommit/handleCreateBranch) -
so a caching proxy sitting in front of the real huggingface.co and this Server
end up with identical state for anything the proxy has touched, and a plain xetd
pointed at the same -data directory afterward serves it with zero migration
step. See internal/casserver's own IngestXorb/IngestShard for the CAS-side
counterpart to this pattern.

Package hubserver's snapshot.go implements Server's persistence, mirroring
casserver's snapshot.go: an atomic (stage-then-rename) JSON dump of every
repo/revision/file this server knows about, and a load of that file on startup.
See casserver/snapshot.go's package doc comment for the full tradeoff writeup
(periodic checkpoint, not a WAL - writes between snapshots are lost on a hard
crash).

Server's live state (repoState/revisionState, each carrying its own
sync.RWMutex) isn't itself JSON-marshalable, so this file defines flat,
mutex-free snapshot structs and converts to/from them.

TYPES

type Server struct {
	CASBaseURL string
	CAS        casInfo

	// Has unexported fields.
}
    Server implements the Hub API shim. CASBaseURL is the base URL of the paired
    casserver.Server instance (e.g. "http://localhost:8420"), handed out via
    the xet-token routes' X-Xet-Cas-Url header. CAS provides the bridge from a
    committed file's plain SHA-256 to its Xet/Merkle hash.

func New(casBaseURL string, cas casInfo) *Server

func (s *Server) FileSHA256s() []string
    FileSHA256s returns the plain SHA-256 of every file any revision of any
    repo lists - the files `hf upload` committed through this shim. The CAS's
    garbage collector keeps these regardless of the keep list a request carries:
    they have no git repo an operator could list them from, and this registry
    is the only record that they are still wanted. Files pushed through the
    git-lfs bridge are not registered here (docs/GIT_LFS.md, known limits),
    which is why that keep list exists.

func (s *Server) HasFile(repoType, repoID, revision, path string) bool
    HasFile reports whether path has been recorded (via a real commit or
    IngestFile) under repoType/repoID/revision.

func (s *Server) HasRepo(repoType, repoID string) bool
    HasRepo reports whether repoType/repoID has been touched locally (created,
    even with no revisions committed to beyond the implicit default). Unlike
    HasRevision/HasFile, no caller embedding this Server currently branches
    on this in production - proxyhub decides whether a request can be served
    locally via HasRevision/HasFile directly, since those already imply the repo
    exists. Exported for test/diagnostic observability (see ingest_test.go and
    proxyhub_test.go).

func (s *Server) HasRevision(repoType, repoID, revision string) bool
    HasRevision reports whether repoType/repoID has revision locally, without
    creating it (unlike getOrCreateRevision's own read side, getRevision, this
    is exported and does not require the caller to already hold a *repoState).

func (s *Server) IngestCommit(repoType, repoID, revision, commitOID string)
    IngestCommit records commitOID as repoType/repoID/revision's current commit
    - for a caller that relayed a real commit write-through to the real Hub
    (which mints the actual commitOID) rather than generating one itself.
    Using the REAL upstream commit OID here, instead of this server's own
    randomCommitOID generator (see commit.go's handleCommit), matters:
    a fabricated OID unrelated to the real repo's actual history would make
    X-Repo-Commit lie about what was actually committed upstream.

func (s *Server) IngestFile(repoType, repoID, revision, path, sha256Hex string, size int64, xetHash merklehash.Hash)
    IngestFile records path's existence and metadata within
    repoType/repoID/revision as if it had been committed - for a caller that
    learned about it from an upstream tree-listing or resolve response rather
    than a real commit ndjson payload. xetHash may be the zero Hash if not
    yet known (matching a freshly-committed file before resolve.go's lazy CAS
    backfill runs - see fileRef's own doc comment); callers that do already know
    it (e.g. a tree-listing response's xetHash field, or a resolve response's
    X-Xet-Hash header) should pass it so a subsequent local resolve doesn't need
    its own CAS lookup.

func (s *Server) IngestRepoInfo(repoType, repoID, revision string)
    IngestRepoInfo ensures repoType/repoID/revision exist locally - the
    same side effect handleRepoInfo's own repo/revision lookups already have
    (getOrCreateRepo always creates on first touch; a revision is only created
    here, not looked up, so this always leaves it present afterward, unlike
    handleRepoInfo's read-only getRevision check). A caller that only learned
    "this repo/revision exists" from an upstream repo-info response - with no
    actual file contents yet - uses this alone; IngestFile (below) is for when
    file contents are also known.

func (s *Server) LoadSnapshot(path string) error
    LoadSnapshot reads a snapshot previously written by Snapshot and restores
    s's repos/revisions/files from it. Intended to be called once, before s
    starts serving any traffic. A missing file at path is not an error (a fresh
    server with no prior snapshot).

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request)

func (s *Server) SetAuthenticator(a auth.Authenticator)
    SetAuthenticator replaces this server's Authenticator (default
    auth.NoAuth{}, i.e. no enforcement - this server's pre-v0.8.0 behavior).
    Safe to call at any time - unlike casserver's SetAuthenticator, hubserver's
    routes dispatch by parsing the path inside each handler rather than
    registering one mux pattern per logical endpoint, so there's no route table
    to rebuild.

func (s *Server) SetLockDir(dir string) error
    SetLockDir stores git-lfs locks as write-once files under dir instead of in
    memory, so several replicas sharing a synced folder agree on who holds what
    (see lockstore.go). Call before serving.

func (s *Server) SetTokenMinter(m auth.TokenMinter)
    SetTokenMinter replaces the minter behind the xet-{read,write}-token routes
    and the git-lfs batch actions. Pass the same auth.SignedTokenAuth the paired
    CAS authenticates with, so tokens this server issues are accepted there.

func (s *Server) SetTokenTTL(ttl time.Duration)
    SetTokenTTL sets the lifetime of minted tokens (default one hour).
    Non-positive values are ignored.

func (s *Server) Snapshot(path string) error
    Snapshot serializes s's repos/revisions/files to path via the same
    stage-to-temp-then-rename pattern casserver.Server.Snapshot and
    storage/fsstore.Store.Put both use, for the same reason: a reader must never
    observe a partially-written file.

    As with casserver's Snapshot, this briefly RLocks each repo/revision
    in turn rather than holding one lock across the whole operation - this
    server's own locking design (see the package doc comment) is already
    per-repo/per-revision specifically so unrelated repos don't contend, and a
    snapshot is not a stronger consistency boundary than any other multi-repo
    read already provides.
```
