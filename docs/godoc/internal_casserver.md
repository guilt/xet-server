# `github.com/guilt/xet-server/internal/casserver`

```
package casserver // import "github.com/guilt/xet-server/internal/casserver"

Package casserver implements the wire-compatible CAS (Content Addressable
Storage) HTTP API real Xet clients (hf_xet/xet-core, and by extension the `hf`
CLI) speak, per xet-core's own openapi/cas.openapi.yaml:

  - POST /v1/xorbs/{prefix}/{hash} - upload a serialized xorb
  - POST /v1/shards - upload a serialized shard
  - GET /v1/reconstructions/{file_id} - file -> xorb/chunk-range map
  - GET /v1/xorbs/{prefix}/{hash} - fetch raw (compressed) xorb bytes
    (byte-serving endpoint for the URLs handed out in fetch_info; not part of
    the public CAS API surface, but needed since this server plays both the
    CAS metadata role and the byte-transfer role real Xet splits across two
    services)
  - GET /v1/chunks/{prefix}/{hash} - global chunk dedup lookup: returns the
    raw bytes of whichever uploaded shard referenced this chunk hash (the real
    wire contract per xet-core's openapi spec - a client parses the returned
    shard itself to find dedup-eligible chunks), 404 if no uploaded shard ever
    referenced it
  - GET /v2/reconstructions/{file_id} - multi-range-optimized file ->
    xorb/chunk-range map (same underlying data as V1, grouped by xorb instead of
    one entry per term)
  - POST /v1/telemetry - no-op ack
  - GET /v1/storage-stats - eviction policy stats (operator-facing; not part of
    the real Xet CAS API)

This server never decompresses chunk payloads - like real CAS, it stores
and serves xorb bytes as opaque blobs, and integrity is checked via the xorb
footer's own hash tree rather than by re-verifying chunk contents.

Every route above except telemetry and storage-stats requires the scope real
xet-core's own OpenAPI spec documents for it (read for every GET, write for
the two uploads), enforced via auth.Authenticator - see SetAuthenticator.
The default (auth.NoAuth{}) enforces nothing, this server's behavior prior to
v0.8.0.

Package casserver's snapshot.go implements Server's persistence: a periodic (and
shutdown-time) atomic write of every in-memory index to a single JSON file,
and a load of that file on startup. This is deliberately NOT a write-ahead
log - writes between snapshots are lost if the process is killed (not just
if it exits cleanly); see docs/PROTOCOL.md's persistence section for the
full tradeoff writeup and why this was chosen anyway (atomic-swap is simple,
needs no new dependency, and reuses the exact staging-file-then-rename pattern
storage/fsstore.Store.Put already relies on for the same reason: a reader must
never observe a half-written result).

CONSTANTS

const (
	V1 = "/v1"
	V2 = "/v2"

	XorbsPath  = V1 + "/xorbs/{prefix}/{hash}"
	ShardsPath = V1 + "/shards"
	// ShardsPathUnversioned is where xet-core >= 1.5 (git-xet 0.2, recent
	// hf_xet) POSTs shards: cas_client/src/remote_client.rs builds
	// "{endpoint}/shards" with no version segment, while the openapi
	// spec still documents /v1/shards. Both are served identically;
	// cmd/xetd mounts this one at the root of the CAS mux.
	ShardsPathUnversioned = "/shards"
	// Deliberately NOT served: POST /v2/shards. Current hf_xet tries it
	// first, but v2 is a different protocol - the response is a stream
	// of newline-delimited JSON progress frames with a "type" field, and
	// the v1 body {"result":1} makes the client fail with "failed to
	// parse shard upload progress frame". A 404 there makes it fall back
	// to the v1 path, which is what this server speaks (PROTOCOL.md #16).
	ReconstructionsPath   = V1 + "/reconstructions/{file_id}"
	ReconstructionsPathV2 = V2 + "/reconstructions/{file_id}"
	ChunksPath            = V1 + "/chunks/{prefix}/{hash}"
	TelemetryPath         = V1 + "/telemetry"
	StoragestatsPath      = V1 + "/storage-stats"
)
    V1/V2 are this server's URL version prefixes - exported so cmd/xetd can
    reference them directly when wiring routes onto its own top-level mux,
    instead of re-typing "/v1"/"/v2" as a raw literal at the call site.
    V2 exists solely for the multi-range-optimized reconstruction endpoint;
    every other route here is V1.

    XorbsPath, ShardsPath, ReconstructionsPath, ChunksPath, TelemetryPath,
    and StoragestatsPath are the specific literal sub-paths (relative to
    V1) this package registers below, also exported so any other package
    referencing one of these paths (cmd/xetd, internal/landingpage, a future
    client) uses the same named constant instead of a duplicated string literal.
    ReconstructionsPathV2 is the V2 counterpart of ReconstructionsPath.

const ClientShardCacheLifetime = 21 * 24 * time.Hour
    ClientShardCacheLifetime is how long a xet client keeps the shards
    of its own uploads in its cache and dedups against them without
    asking the server: MDB_SHARD_LOCAL_CACHE_EXPIRATION in xet-core's
    xet_data/src/processing/constants.rs (3 weeks, as of xet-core 1.6).

const DefaultGCGrace = ClientShardCacheLifetime + 24*time.Hour
    DefaultGCGrace is the grace period Collect applies when the request does
    not name one: the client cache lifetime plus a day of margin for clock
    differences and a push that started just before the cutoff.

const GCPath = V1 + "/gc"
    GCPath is where cmd/xetd mounts GCHandler on the CAS port. It is not
    registered by Server.routes on purpose: a Server embedded in xet-proxyd is
    a cache and must never get a route that deletes by keep set, so only the
    standalone binary wires it.


VARIABLES

var ErrContentUnavailable = errors.New("casserver: content not yet available on this replica")
    ErrContentUnavailable is returned (via errors.Is) by ReconstructFile and
    reported by MissingXorbs when a file's shard is known but at least one xorb
    it references is not in this replica's store yet. On a synced folder that is
    the normal state of a file another machine pushed moments ago; the caller
    should ask the client to retry.

var ErrGCUnsupported = errors.New("casserver: storage backend cannot enumerate and delete blobs")
    ErrGCUnsupported is returned by Collect when the storage backend cannot
    enumerate and delete its blobs (s3store today).

var ErrMalformedXorb = errors.New("casserver: malformed xorb")
    ErrMalformedXorb is returned (wrapped) by IngestXorb when r's bytes don't
    parse as a valid chunk stream (see xorbformat.DeriveFooter) - maps to a 400
    at handleUploadXorb's HTTP boundary.

var ErrRangeNotSatisfiable = errors.New("casserver: range not satisfiable")
    ErrRangeNotSatisfiable is returned (via errors.Is) by ReconstructFile when
    [start, end] falls outside the file.

var ErrUnknownFile = errors.New("casserver: unknown file")
    ErrUnknownFile is returned (via errors.Is) by ReconstructFile when no
    uploaded shard has described fileHash.

var ErrXorbHashMismatch = errors.New("casserver: xorb hash in URL does not match hash computed from chunk contents")
    ErrXorbHashMismatch is returned (wrapped) by IngestXorb when claimedHash
    doesn't match the hash independently computed from r's chunk contents - maps
    to a 400 at handleUploadXorb's HTTP boundary.


TYPES

type GCHandlerConfig struct {
	// DefaultGrace applies when the request names none.
	DefaultGrace time.Duration
	// ExtraKeep, if set, returns OIDs to keep in every run regardless
	// of the request (the Hub shim's file registry).
	ExtraKeep func() []string
	// AfterCollect, if set, runs after a collection that was not a dry
	// run: the place to snapshot. Its error is reported in the
	// response but the collection stands.
	AfterCollect func() error
	// Disabled, if non-empty, makes every request fail with 409 and
	// this reason (synced-folder mode).
	Disabled string
}
    GCHandlerConfig wires the parts of a collection that live outside this
    package.

type GCOptions struct {
	// Keep lists the hex SHA-256 of every file to keep, as git-lfs names
	// them (the OID in the pointer). Case-insensitive. An OID no shard
	// describes is counted in the report, not an error: it may be a
	// pointer whose object was never pushed, or one still in transit.
	Keep []string
	// Grace protects any xorb uploaded, fetched or advertised more
	// recently than this, and any xorb file that recently changed on
	// disk, from deletion in this run. Zero means no grace; see the
	// file comment before passing less than DefaultGCGrace.
	Grace time.Duration
	// DryRun computes and reports everything and changes nothing.
	DryRun bool
}
    GCOptions is one collection's input.

type GCReport struct {
	DryRun       bool  `json:"dry_run"`
	GraceSeconds int64 `json:"grace_seconds"`

	// KeepOIDs is how many distinct OIDs the keep set had; KeepUnknown
	// how many of them no shard describes (sample in KeepUnknownSample).
	KeepOIDs          int      `json:"keep_oids"`
	KeepUnknown       int      `json:"keep_unknown"`
	KeepUnknownSample []string `json:"keep_unknown_sample,omitempty"`

	// FilesKept counts every file that stays; FilesRecent is the part of
	// it kept only because its shard arrived inside the grace period (a
	// push whose pointer the keep list could not name yet).
	FilesKept    int `json:"files_kept"`
	FilesRecent  int `json:"files_recent"`
	FilesDropped int `json:"files_dropped"`

	ShardsKept      int `json:"shards_kept"`
	ShardsRewritten int `json:"shards_rewritten"`
	ShardsDeleted   int `json:"shards_deleted"`

	// XorbsKept are referenced by a kept file. XorbsDeleted were not and
	// are gone (or, in a dry run, would be). XorbsDeferred were not
	// referenced either but are inside the grace period or being
	// fetched right now; a later run reconsiders them.
	XorbsKept          int   `json:"xorbs_kept"`
	XorbsKeptBytes     int64 `json:"xorbs_kept_bytes"`
	XorbsDeleted       int   `json:"xorbs_deleted"`
	XorbsDeletedBytes  int64 `json:"xorbs_deleted_bytes"`
	XorbsDeferred      int   `json:"xorbs_deferred"`
	XorbsDeferredBytes int64 `json:"xorbs_deferred_bytes"`

	// Errors are per-item failures (a xorb that could not be deleted, a
	// shard that could not be parsed) that did not stop the run.
	Errors []string `json:"errors,omitempty"`
}
    GCReport is what one collection did, or (DryRun) would do.

type GCRequest struct {
	Keep []string `json:"keep"`
	// GraceSeconds overrides the server's default grace when present
	// (0 is "no grace"; see the file comment).
	GraceSeconds *int64 `json:"grace_seconds,omitempty"`
	DryRun       bool   `json:"dry_run"`
}
    GCRequest is POST GCPath's JSON body.

type Server struct {
	// Has unexported fields.
}
    Server implements the CAS HTTP API against a storage.Store backend for xorb
    bytes. File-reconstruction and xorb-footer indexes are held in memory:
    they are metadata derived from uploaded shards/xorbs, cheap to rebuild,
    and small relative to the bulk chunk data in Store.

    Each index has its own mutex rather than one shared lock: none of the four
    maps are ever read or written together under one critical section (confirmed
    - no code path needs a consistent snapshot across more than one of them), so
    a single global lock only serialized unrelated concurrent uploads/downloads
    without buying any actual consistency guarantee. Splitting them lets a
    large xorb upload (which only touches xorbFooters/xorbRawLength) proceed
    concurrently with an unrelated reconstruction lookup (which only touches
    fileRecon).

    xorbLastAccess/xorbInFlight exist purely to support eviction.Sweeper (see
    EvictionCandidates/ForgetKey below): the last time each xorb was uploaded
    or fetched, and how many fetches are in progress right now, so a sweep never
    deletes a blob a client might be mid-download of.

func New(xorbs storage.Store) *Server

func (s *Server) Collect(ctx context.Context, opts GCOptions) (GCReport, error)
    Collect runs one garbage collection: see the file comment for what it keeps
    and deletes and why. Safe to call on a serving server; uploads and shard
    scans wait while the index is rebuilt (a few seconds for a large index),
    downloads do not. The caller should snapshot right after a run that changed
    anything (GCHandlerConfig.AfterCollect), so a crash cannot restore an index
    that still advertises deleted xorbs.

func (s *Server) EvictionCandidates() []eviction.Candidate
    EvictionCandidates implements eviction.Registry: every xorb this server
    knows about, excluding any with a fetch currently in progress. Called by
    eviction.Sweeper on its own poll interval, not a request hot path.

func (s *Server) FileSize(fileHash merklehash.Hash) (int64, bool)
    FileSize returns the total unpacked size of a file known to this server's
    reconstruction index, or false if fileHash is unknown.

func (s *Server) ForgetKey(key string)
    ForgetKey implements eviction.Registry: drops key from every in-memory index
    once eviction.Sweeper has already deleted the underlying blob from storage.
    A subsequent fetch of this xorb 404s, exactly as if it had never been
    uploaded - a client that still needs it must re-upload (real Xet clients
    already handle a missing xorb by re-deriving it from the source file,
    since CAS storage is explicitly not guaranteed permanent).

func (s *Server) GCHandler(cfg GCHandlerConfig) http.Handler
    GCHandler serves POST GCPath: Collect with the request's keep set
    plus cfg.ExtraKeep, answering with the GCReport as JSON. Requires
    auth.ScopeAdmin, which only the operator's shared secret carries (or every
    request, with no auth configured).

func (s *Server) HasFileRecon(fileID merklehash.Hash) bool
    HasFileRecon reports whether this server already has a complete
    reconstruction on file for fileID - a caller embedding this Server uses this
    to decide whether a reconstruction request can be served entirely from local
    state or needs an upstream fetch (+ IngestFileRecon) first.

func (s *Server) HasXorbBytes(ctx context.Context, hash merklehash.Hash) (bool, error)
    HasXorbBytes reports whether hash's raw bytes are present in this server's
    storage backend - distinct from HasXorbFooter (footer/size indexing and
    blob storage are updated together by IngestXorb/ handleUploadXorb, but a
    caller embedding this Server may want to confirm both independently, e.g.
    after a restart with a stale index).

func (s *Server) HasXorbFooter(hash merklehash.Hash) bool
    HasXorbFooter reports whether this server has a footer indexed for hash -
    a caller embedding this Server (see IngestXorb's doc comment) uses this to
    decide whether a reconstruction it's about to serve can be built entirely
    from local state, or needs to fetch/ingest the xorb first.

func (s *Server) IngestFileRecon(fileID merklehash.Hash, entries []shardformat.FileDataSequenceEntry)
    IngestFileRecon records fileID's complete reconstruction entries as if a
    shard had described it - for a caller embedding this Server as a caching
    layer (e.g. internal/proxycas) that learned a file's reconstruction from
    an upstream CAS response rather than from a real shard upload. entries
    must be the file's COMPLETE ordered term list (not a byte-range-clipped
    subset - see internal/proxycas's own handleReconstruction doc comment for
    why a Range-limited upstream response can never safely populate this):
    reconstructionWindow and every downstream reader assumes fileRecon[fileID]
    represents the whole file, and a caller that violates that would silently
    truncate every future request for it.

func (s *Server) IngestShard(body []byte) error
    IngestShard parses body as a serialized shard and merges its
    file-reconstruction entries into this server's in-memory fileRecon index
    (keyed by file hash), and indexes every chunk hash referenced by the shard's
    xorb-info section against body itself, backing the global chunk-dedup lookup
    (GET /v1/chunks/{prefix}/{hash} - see handleChunkDedup): the real wire
    contract for that endpoint is "return the shard bytes that reference this
    chunk," which a real client parses itself to discover chunks it can dedup
    against without re-uploading - see docs/PROTOCOL.md's global-dedup section
    for the full story of how this was confirmed against xet-core's own client
    source.

    Exported so a caller embedding this Server as a caching layer (e.g.
    internal/proxyhub or internal/proxycas, relaying a real client's shard
    upload write-through to a real upstream CAS and wanting this server to
    also reflect it immediately) can feed it shard bytes through the identical
    parsing/indexing path handleUploadShard uses.

func (s *Server) IngestXorb(ctx context.Context, claimedHash merklehash.Hash, r io.Reader) (written bool, err error)
    IngestXorb validates, stores, and indexes a xorb's raw chunk-stream bytes
    (read from r, with no footer - see handleUploadXorb's doc comment on why:
    real hf_xet clients never send one) under claimedHash, exactly as a real
    client's upload would. Returns written=true if this was a new xorb (false if
    claimedHash was already present - Put's normal dedup semantics).

    Exported so a caller embedding this Server as a caching layer (e.g.
    internal/proxycas, wrapping this server instead of reimplementing its
    upload-validation/indexing logic independently) can feed it xorb bytes
    fetched from elsewhere - an upstream CAS response, not an HTTP request
    body - through the identical validation and storage path a real upload goes
    through, so anything this method accepts is guaranteed servable afterward
    the same way a directly-uploaded xorb is.

func (s *Server) LoadSnapshot(path string) error
    LoadSnapshot reads a snapshot previously written by Snapshot and restores
    s's indices from it. Intended to be called once, before s starts serving
    any traffic - it does not itself take any of s's per-index locks, since
    a freshly-constructed Server (via New) has no concurrent access to race
    against yet. A missing file at path is not an error (a fresh server with no
    prior snapshot); any other read/parse failure is returned so the caller can
    decide whether to start fresh or abort startup.

func (s *Server) MissingXorbs(ctx context.Context, fileHash merklehash.Hash) ([]merklehash.Hash, error)
    MissingXorbs reports which xorbs the file identified by fileHash needs that
    this replica does not have (or has only partially, from a sync in progress).
    ErrUnknownFile if no shard describes the file. An empty result means
    ReconstructFile can serve the whole file now.

func (s *Server) ReconstructFile(ctx context.Context, fileHash merklehash.Hash, start, end int64, w io.Writer) error
    ReconstructFile writes bytes [start, end] (inclusive, like an HTTP Range) of
    the file identified by fileHash to w, decompressing each chunk from its xorb
    on the way out. A zero-length file is served for start == 0 and end == -1
    only. Every xorb touched is marked in flight for the duration so an eviction
    sweep cannot delete it mid-stream.

    The write to w may have started when an error is returned (a xorb missing
    from storage, a corrupt chunk), so a caller streaming an HTTP body cannot
    turn a late error into a clean status code; it should log it and drop the
    connection, and the client's own SHA-256 check (git-lfs verifies every
    download) catches the truncation.

func (s *Server) RunRescanLoop(ctx context.Context, interval time.Duration)
    RunRescanLoop calls ScanShards every interval until ctx is done. For a
    replica on a synced folder this is how it notices other machines' uploads
    before any client asks for them (so their chunks take part in dedup on the
    next push here).

func (s *Server) ScanShards(ctx context.Context) (added int, err error)
    ScanShards indexes every shard file in the shard dir that this server has
    not indexed yet. A file is only trusted if its content hashes to its name:
    a sync tool's half-delivered file (or anything else in the directory) fails
    that check and is skipped until a later scan sees it whole. Returns how many
    shards were newly indexed. Safe to call concurrently with requests.

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request)

func (s *Server) SetAuthenticator(a auth.Authenticator)
    SetAuthenticator replaces this server's Authenticator (default
    auth.NoAuth{}, i.e. no enforcement - this server's pre-v0.8.0 behavior).
    Must be called before serving any traffic, for the same route-rebuild reason
    as SetUploadRateLimiter. See auth.Authenticator's doc comment for how to
    implement a custom one.

func (s *Server) SetEvictionStats(statsFunc func() eviction.Stats)
    SetEvictionStats wires an eviction.Sweeper's Stats method into GET
    /v1/storage-stats, so the eviction policy's effect is observable via the
    running server rather than only inferable from logs. Call once at startup if
    an eviction.Sweeper was created for this server's store.

func (s *Server) SetFetchURLSigner(m auth.TokenMinter, ttl time.Duration)
    SetFetchURLSigner makes the xorb fetch URLs in reconstruction responses
    carry a read token minted by m for the requesting principal, valid for ttl,
    whenever the storage backend cannot presign. Needed as soon as auth is on:
    xet-core fetches those URLs with no Authorization header (the real CAS
    hands out presigned CDN URLs), so without a credential in the URL every
    hf download failed with 401 while git-lfs downloads, whose batch actions
    carry a header, worked. The same SignedTokenAuth that authenticates requests
    serves as m.

func (s *Server) SetShardDir(dir string) error
    SetShardDir makes s persist every ingested shard body to dir (named by the
    shard's content hash) and rescan dir for shards written by other replicas.
    Call before the first request. It does not scan by itself; call ScanShards
    once after any snapshot has been loaded.

func (s *Server) SetUploadRateLimiter(limiter *ratelimit.Limiter)
    SetUploadRateLimiter wires a per-source-IP token-bucket limiter in front
    of the xorb and shard upload endpoints. Must be called before serving any
    traffic - it rebuilds the route table (http.ServeMux panics on duplicate
    pattern registration, so routes are re-registered from scratch on a fresh
    mux rather than layered on top of the existing one).

func (s *Server) ShardDir() string
    ShardDir returns the directory set by SetShardDir, or "".

func (s *Server) Snapshot(path string) error
    Snapshot serializes s's persistable indices to path via the same
    stage-to-temp-then-rename pattern storage/fsstore.Store.Put uses: a reader
    (a concurrent LoadSnapshot, or a crash mid-write followed by a restart)
    never observes a partially-written file, since os.Rename is atomic on the
    same filesystem.

    Each index's own mutex is taken (briefly, RLock only) to copy its current
    contents before releasing it and proceeding to the next index - this means
    Snapshot does NOT capture one single atomic instant across all indices
    simultaneously (a xorb upload completing between two of this function's
    per-index locks could appear in one snapshot section but not another,
    momentarily-inconsistent slice of the same snapshot file). That's an
    acceptable tradeoff for the same reason the per-index mutex split itself is:
    no code path anywhere in this server ever reads more than one of these
    indices under a single combined invariant, so a snapshot that's internally
    not perfectly instant-consistent across indices restores to a state no
    different from "a few requests landed slightly before or after this snapshot
    was taken" - which is already true of any periodic snapshot regardless of
    locking strategy.

func (s *Server) XetHashForSHA256(sha256Hex string) (merklehash.Hash, bool)
    XetHashForSHA256 returns the Xet/Merkle file hash for a file previously
    uploaded via a shard whose FileMetadataExt declared this SHA-256, or false
    if no such file is known. Used by hubserver to bridge the Hub commit
    API's plain-SHA-256 file identity to the Xet hash the CAS layer indexes
    reconstructions under.
```
