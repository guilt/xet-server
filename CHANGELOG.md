# Changelog

All notable changes to Xet Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.0] - 2026-10-24

Security-hardening release. Authorization-dependent proxy caches are now
scoped to the caller, runtime configuration setters are synchronized, and
the Windows `-race` test path is documented and working. Thanks to
[Taylor Brown (@Tay-Tay)](https://github.com/Tay-Tay) for the garbage-collection patches
and [@stubbi](https://github.com/stubbi) / [openxet](https://github.com/stubbi/openxet)
for the independent implementation and security review.

### Fixed

- **Runtime configuration setters are race-free.** `proxycas`,
  `proxyhub`, and `hubserver` now guard their `Authenticator`,
  rate-limiter, token-minter, and token-TTL fields with a config lock.
  Their setters are documented as usable while serving, but the previous
  plain fields were read per request and written by the setters without
  synchronization.

### Security

- **`xet-proxyd`: authorization-dependent caches are per-credential.** The
  upstream xet-token cache key now includes a SHA-256 fingerprint of the
  caller's `Authorization` header, alongside repo/ref/kind, so one caller's
  read or write token can never be served to an anonymous or wrong-token
  caller. Repo-info, tree, and resolve freshness keys are likewise scoped
  to the credential, and an upstream 401/403 is never hidden behind a stale
  cached token or private-repo metadata (other upstream failures still use
  the offline stale fallback for the same credential). This closes the
  token-cache isolation issue in the openxet report; the keyed, xorb-only
  global-dedup answer issue from the same report was already fixed in
  1.2.0. Token caches and the 401-heal index remain process-memory only;
  a regression test asserts snapshots never contain an upstream access
  token or the caller credential.

## [1.2.0] - 2026-10-24

Full dataset handoff release. The pull-through proxy now caches shared-xorb
slices as synthetic xorbs, so a plain `xetd` can serve deduplicated dataset
files offline after the handoff. This release also brings the Git LFS
bridge, garbage collection, synced-folder mode, and the repo-scoped/keyed
dedup hardening below.

### Added

- **Partial-xorb download slices are cached for offline handoff.** When a
  file's reconstruction cites only some chunks of a xorb shared with other
  files (normal for datasets and deduplicated repos), the proxy now
  repackages each contiguous cited chunk group as a new xorb under its own
  content hash and rewrites the file's terms to reference it. Previously
  such files were relayed live and cached nothing, so a plain `xetd`
  handed the proxy's `-data` directory returned 404 for them. Files whose
  `fetch_info` has a coverage gap still relay live (and download fine);
  they are simply not cached. Verified against the real Hub with a
  `bigcode/the-stack-v2` file whose reconstruction cites a 222-chunk slice
  of a shared xorb: online through the proxy, then offline via `xetd` on
  the same data directory with an identical SHA-256.
- **Synced-folder mode (`-sync-folder`)**: the data directory can be a
  folder shared through Dropbox, Syncthing or a mount, with one xetd per
  machine. Shard bodies are persisted as content-named files, the index
  is rebuilt from them (no snapshots), other replicas' uploads are picked
  up by rescans (periodic, and on lookup misses when the directory's
  mtime moved), files whose xorbs have not synced are refused with a 503
  instead of served truncated, and git-lfs locks become write-once claim
  files with a deterministic election. `docs/GIT_LFS.md` has the design.
- **Shard bodies are always persisted** (`<data>/shards/<hash>`), also
  without `-sync-folder`: an upload survives a crash before the next
  snapshot, and startup re-indexes any shard the snapshot lacks. Xorb
  footers missing from the index are derived from the stored bytes on
  demand.
- **Git LFS server** under `/{owner}/{name}.git/info/lfs` on the Hub port
  (`docs/GIT_LFS.md`): batch responses now carry the per-object `actions`
  the stock `git-lfs` client and `git-xet` need (`xet` transfer for
  uploads, `basic` hrefs for downloads), `GET objects/{oid}` streams a file
  reconstructed from xorbs with `Range` support, and the File Locking API
  (`locks`, `locks/verify`, `locks/{id}/unlock`) is implemented and
  persisted in the hub snapshot.
- **`casserver.ReconstructFile`**: server-side reconstruction of a file
  (or byte range) from its shard terms and xorb chunks, decompressing
  LZ4/BG4 chunks on the way out. Only the LFS bridge uses it; real Xet
  clients still reconstruct client-side.
- **Signed xorb fetch URLs**: with auth on, the URLs a reconstruction
  response hands out for the CAS's own byte-serving endpoint carry a
  read token for the caller in the query string, since xet-core fetches
  them with no Authorization header (the real CAS hands out presigned
  CDN URLs). Before this every `hf download` against an auth-gated
  server failed with 401 on `GET /v1/xorbs/...` while uploads and
  git-lfs downloads worked. Only the xorb GET/HEAD routes accept a token
  from a URL (`integration-tests/multi_client_auth_gated.sh`).
- **Garbage collection for a standalone server** (`xetd gc`, `POST
  /v1/gc`): the operator supplies the LFS OIDs still reachable (`git
  lfs ls-files --all --long` per repo), files committed through the Hub
  shim are kept automatically, and everything else is dropped from the
  shards and deleted from the store, followed by a snapshot. Only the
  shared secret may run it (new `auth.ScopeAdmin`, never minted). A
  grace period (22 days by default) protects any xorb uploaded, fetched
  or advertised in a dedup answer since, and any file whose shard is
  that recent, because a xet client dedups from its own cache for three
  weeks without asking the server; dedup answers now carry a matching
  three-week expiry instead of "never", and xorb last-access times are
  persisted in the snapshot. The route is mounted by `cmd/xetd` only
  (xet-proxyd is a cache; eviction is its tool) and refused with
  `-sync-folder`. `integration-tests/gc_reclaims_unreferenced.sh`.
- **`auth.SignedTokenAuth`**: with a shared secret, the Hub shim now mints
  HMAC-signed, scoped, expiring CAS tokens instead of random strings the
  CAS could not accept when auth was on. Also accepts the secret as an
  HTTP Basic password (the only shape git-lfs can send); the user name
  becomes the Principal's subject and the owner of locks. `-token-ttl`
  sets the lifetime.
- **Newer xet-core clients**: `POST /shards` (unversioned, what git-xet
  0.2.1 and recent hf_xet actually call) is served alongside
  `/v1/shards`. (The global-dedup prefix those clients send is covered
  under Fixed below.)
- **Multi-client integration tests.** `integration-tests/multi_client_*.sh`
  run the real `hf` CLI as several machines (each with its own `HF_HOME`,
  `HF_XET_CACHE` and token) against one `xetd`, and assert from the
  server's DEBUG log and the client's own log that the cross-client path
  ran: a stranger's upload deduplicated against another machine's file
  (the two fixes below were invisible to every single-cache test),
  identical bytes from a second machine stored nothing, and machines that
  never uploaded downloading by name and as a whole repo. A script can
  now declare its own budget with a `# XET_IT_TEST_TIMEOUT: N` header.

### Fixed

- **Global-dedup responses are complete shard files.** Clients upload
  shards with the footer and lookup tables stripped, but load what they
  download from `GET /v1/chunks/{prefix}/{hash}` with a reader that
  requires footer version 1. Serving the uploaded bytes back unchanged
  therefore failed on any client that had not produced them itself: with
  git-xet 0.2.1 pushing from a second machine, every push that hit a
  dedup match died with "Expected footer version 1, got 0". The server
  now rebuilds a footer-carrying shard from the parsed upload, at ingest
  and when loading a snapshot written by an earlier build.
- **Global-dedup queries accept the prefix real clients send.**
  `GET /v1/chunks/{prefix}/{hash}` only accepted the OpenAPI spec's
  `default-merkledb`; xet-core >= 1.5 (hf_xet 1.6.0, git-xet 0.2.1)
  queries with `default`, the xorb prefix, and was answered 400 on every
  query. The client treats that as "not found", so a second machine
  uploading a near-identical copy of a file the server already had
  re-uploaded all of it. Both prefixes are now accepted.
- **Global-dedup answers cover the file, not just the shard that
  introduced the chunk.** An upload shard lists only the xorbs that
  upload created, so a chunk born in a small edit mapped to a two-chunk
  answer; a client queries a file's first chunk and then at most once
  per 256 chunks, so a second machine editing a file with an edited
  history learned two chunks and re-uploaded the rest (42 MB of a 40 MB
  file). The answer is now assembled from the chunk's xorb plus every
  xorb of every file referencing it (xorb-info only, like xet-core's
  reference client; capped at 65536 chunk entries).

### Security

- **Minted tokens are repo-scoped.** The Hub shim's HMAC-signed
  tokens now carry the repo type and ID inside the signed payload (format
  `xst2`), and every repo-addressed Hub route - token minting, repo info,
  tree, resolve, preupload, commit, branch, and all git-lfs batch/object/
  lock routes - rejects a token for a different repo with 403. A
  repo-scoped write token may create a new repo only inside its own
  namespace; creating elsewhere requires the shared secret. Tokens from
  the previous unscoped `xst1` format are refused.
  `integration-tests/repo_scope.sh`.
- **Global-dedup answers are keyed.** `GET /v1/chunks/...` now
  returns an xorb-only shard whose chunk hashes are BLAKE3-keyed with a
  fresh random 32-byte key per response (footer `chunk_hash_hmac_key`),
  matching xet-core's `export_as_keyed_shard`, and carries no
  file-reconstruction entries. Previously the key was zero, so a caller
  holding one chunk could learn the raw hashes of every other chunk (and
  file hashes) in the matching xorbs.
## [1.1.0] - 2026-09-15

### Fixed

- **`xet-proxyd`: expired Xet access tokens no longer abort long downloads
  with a baffling `401`.** Xet's per-repo access tokens are short-lived,
  and on a long, high-concurrency download (e.g. `hf download` of a
  900+-file dataset) a token can expire between the client's refresh and
  the moment a file's reconstruction is requested from the real CAS, which
  answers `401 Unauthorized` for a repo the client was just downloading
  from successfully. The proxy previously relayed that 401 verbatim (its
  documented relay-4xx-as-is policy), failing the whole download. It now
  detects the 401 on the CAS-facing port, mints a fresh replacement token
  from the real Hub using the **same credential the client already
  presented** (never a secret the proxy holds itself, and scoped to the
  same repo/ref/read-vs-write kind - so it can only restore access the
  client already had), and retries the request once. The heal covers every
  upstream CAS fetch: reconstruction (`v1`/`v2`), xorb GET and HEAD, and
  chunk-dedup lookup - see `internal/proxycas`'s `fetchCASWithHeal` and
  `internal/proxyhub`'s `FreshXetTokenFor`. Backward compatible: without a
  token refresher wired in (any non-`xet-proxyd` caller of
  `internal/proxycas`), an upstream 401 is still relayed unchanged.

- **`xet-proxyd`: a cached xet token past its `exp` is never served.** The
  stale-fallback for `xet-{read,write}-token` responses previously served
  whatever was cached when a live refresh failed, regardless of the cached
  token's expiry - so one transient upstream failure at token-rollover time
  handed the client a token that was dead on arrival (guaranteeing the 401
  above). The fallback now refuses to serve a cached token whose `exp` is
  within 60 seconds of now or already past, surfacing the upstream error
  instead - a clean, retryable failure. See `internal/proxyhub`'s
  `tokenSafetyMargin`.

### Added

- **`internal/proxyhub.Server.FreshXetTokenFor` and
  `internal/proxycas.WithTokenRefresher`** - the two surfaces the 401 heal
  is built on. The Hub-facing proxy records each relayed xet access token
  alongside the exact Hub call parameters and the caller's credential that
  minted it (a bounded index, so it can mint a fresh replacement on demand
  without ever holding a credential of its own); `cmd/xet-proxyd`'s
  CAS-facing middleware installs that refresher into the request context so
  `fetchCASWithHeal` can retry a rejected fetch.

## [1.0.0] - 2026-09-12

The first tagged release with a proper distribution story - the Go module
path is now `github.com/guilt/xet-server` (matching the repository), so all
three binaries are installable via `go install`, and every tag now builds,
tests, and ships through GitHub Actions as per-platform release zips that
bundle the binaries **and** the documentation (README, CHANGELOG, LICENSE,
CONTRIBUTING, `docs/` - Markdown sources plus the browsable `make docs`
HTML with Mermaid diagrams rendered to SVG), plus a `checksums.txt`.

This release also makes `xet-proxyd` genuinely work against the **real**
huggingface.co, end to end. v0.9.0's proxy was verified against this
project's own local stand-in servers; this release closes every gap found
by actually pointing it at the live Hub and the real `hf` CLI - several of
which silently broke uploads or downloads through the proxy against the
real Hub (listed under **Fixed** below). A local 32-bit build of `hf_xet`
(from the published sdist, patched for i686) was used to exercise the real
client through the proxy; the download path was verified byte-identical
against a direct download, and a real upload to the Hub through the proxy
was verified on the live service.

A second round of hardening then came from driving that same real client
at **scale**: multi-GB model files and a 917-file dataset, rather than the
small single-repo fixtures the suite had used. That exposed a further set
of gaps invisible to small-file, model-only testing - uploads above the
LFS threshold never entering the Xet path at all, whole-repo downloads
aborting inside `tqdm`, dataset URLs 404ing, and a snapshot loop that
exhausted memory (taking `file_recon` persistence down with it) once the
chunk index grew past a few hundred thousand entries. It also established
a real, structural limit on what a pull-through proxy can cache, now
documented rather than papered over (see **Known limitations**).

### Added
- **`go install` support**: the module path changed from the bare local
  name `xet-server` to `github.com/guilt/xet-server`, the single change
  that makes `go install github.com/guilt/xet-server/cmd/{xetd,xet-proxyd,xet}@latest`
  work at all (a module path must match the repository for the `@version`
  resolution to find it). All `xet-server/internal/...` import paths
  updated to match. `scripts/build_docs.go`'s repo-root discovery and
  `go doc` package-name trimming were updated to the new module path;
  `scripts` remains its own module and is unaffected.
- **GitHub Actions release workflow** (`.github/workflows/build-release.yaml`,
  modeled on `gsum`'s): on every `v*.*.*` tag push a `docs` job installs
  `mmdc`/mermaid-cli through `bun` and runs `make docs`; the build matrix
  then builds all three binaries with `CGO_ENABLED=0` for 26 OS/arch
  targets (linux/windows/darwin x amd64/arm64/386/arm, plus
  riscv64/ppc64le/s390x and the BSDs/solaris/dragonfly), compresses with
  UPX where supported, runs `go test ./...` on linux-amd64, and uploads
  each platform's **raw staging directory** as an artifact (binaries +
  `README.md`, `CHANGELOG.md`, `LICENSE.md`, `CONTRIBUTING.md`, `docs/*.md`,
  the `docs/html/` HTML site, and a `VERSION` file). The release job
  downloads those raw artifacts, creates each
  `xet-server-<tag>-<platform>.zip` exactly once, computes `checksums.txt`
  (SHA-256 of every zip) on the final zips, and attaches everything to the
  GitHub Release. Artifacts are raw directories rather than zips so
  GitHub's artifact-download zip-wrapping can't produce a zip-within-a-zip.
- **GitHub Actions CI workflow** (`.github/workflows/ci.yaml`): on every
  push to `main` and every PR - `go mod tidy`, a `gofmt` formatting check,
  `go vet`, `go build`, and `go test ./...` on ubuntu-latest.
- **README Install section**: `go install` instructions for all three
  binaries (installing into `$(go env GOPATH)/bin`) and a pointer to the
  per-platform release zips on the GitHub Releases page.
- **Regression tests for every real-HF proxy fix below**: unit tests in
  `internal/hfclient` (resolve redirect semantics, Content-Type headers,
  `RelayRaw` verbatim forwarding, presigned-URL fetch), `internal/proxyhub`
  (upstream-error body relay, raw preupload/commit relay, live Git LFS
  relay), and `internal/proxycas` (presigned-URL xorb caching, range
  concatenation, direct-fetch fallback); plus a new no-pipenv integration
  test, `integration-tests/xet_proxyd_write_relay.sh`, that drives
  create-repo/preupload/commit through the proxy against a local stand-in
  upstream.
- **git-LFS batch endpoint in `xetd`**
  (`POST /{repo_id}.git/info/lfs/objects/batch`), answering
  `{"transfer": "xet", "objects": [{oid, size}]}`. This is what actually
  routes a real client into the Xet upload path: `huggingface_hub` offers
  the server `["basic", "multipart", "xet"]` and branches on the reply, so
  without this endpoint every file above the ~5 MB LFS threshold fell back
  to plain LFS and failed against a server that implements only Xet. Files
  below the threshold commit inline and never hit it, which is why a
  small-file round-trip test passed against a server missing it entirely.
  See PROTOCOL.md section 13.
- **`siblings` in `repo-info`** (`hubserver`, `hfclient`, `proxyhub`).
  `snapshot_download` - what `hf download` uses for any multi-file request
  - falls back to `list_repo_tree` when `siblings` is empty, and that
  fallback hands a *generator* to `tqdm`'s `thread_map`, whose
  `_min_map_len` filters out unknown-length iterables and then raises
  `ValueError: min() arg is an empty sequence` before fetching anything.
  Returning a populated `siblings` avoids the fallback entirely. See
  PROTOCOL.md section 14.
- **Dataset and Space support on resolve and LFS-batch URLs.** Resolve
  paths are `datasets/{ns}/{name}/resolve/...` and
  `spaces/{ns}/{name}/resolve/...`, while models are unprefixed. Both
  servers now locate the `/resolve/` marker and read the two segments
  before it as `{namespace}/{name}`, so an unrecognized future prefix
  degrades to `model` instead of 404ing. `repoType` is threaded into the
  upstream call (resolving a dataset at the model URL makes the real Hub
  answer `404 RepositoryNotFound`) and into `X-Xet-Refresh-Route`, which
  must be typed or a mid-download token refresh targets a nonexistent
  model. See PROTOCOL.md section 15.
- **OpenAPI spec and landing pages cover the above.** The spec gained the
  `/{repo_id}.git/info/lfs/objects/batch` path with its request/response
  schemas and documented bounds, `siblings` on `RepoInfoResponse` (whose
  description previously claimed "only ever reads sha" - no longer true),
  and the repo-type prefix forms on resolve. Both Hub landing pages list
  the batch endpoint. `internal/apidocs`' spec test now asserts the batch
  path and `siblings` are present, so the spec can't silently drift from
  the handlers again.
- **`docs/MIRRORING.md`** gained section 9.1 (what a pull-through proxy
  can and cannot cache), section 10 (building a guaranteed-complete
  offline library via download-then-upload), and section 11 (Windows
  specifics: 64-bit Python, `HF_TOKEN` and local auth, `.exe` names).
- **Fuzz coverage for textual (not just binary) attacker input.** Every
  existing fuzz target covered a wire format; nothing covered the URL
  paths parsed straight off the request line, pre-auth. Five new targets:
  `FuzzParseResolvePath`, `FuzzExtractRepoIDBefore`,
  `FuzzRepoTypeFromPrefix`, `FuzzLFSBatchHandler` (arbitrary bodies
  through the batch endpoint over a real `httptest` server), and
  `FuzzSnapshotRoundTrip` (v2 snapshot fidelity plus an assertion that
  on-disk size scales with distinct shard bodies, not with referencing
  chunks). 16 targets total.
- **`make test-race`, `make test-fuzz`, `make fuzz-seeds`.**
  `test-fuzz` depends on `fuzz-seeds` so committed crash regressions
  replay before any time is spent hunting new inputs. Kept separate from
  `-race` deliberately: the race detector costs ~10x execution speed,
  which within a fixed fuzz budget means far fewer inputs explored.
- **CI now runs the integration suite.** It previously ran unit tests
  only, so the entire `hf`-CLI compatibility surface - the thing this
  project exists to guarantee - was never exercised on a push. The new
  job installs `pipenv` + `huggingface_hub`/`hf_xet`, without which the
  two real-client tests skip via exit 77 and CI reports green while
  covering none of it. CI also replays the fuzz corpus under `-race` and
  runs a short 20s-per-target hunt.
- **Swagger UI is now served on the Hub port as well as the CAS port**
  (both `xetd` and `xet-proxyd`). The spec documents two APIs that run on
  two listeners, but the UI was only mounted on `-addr` - so "Try it out"
  could never reach a Hub endpoint: a cross-port call is cross-origin and
  this server sends no CORS headers (deliberately - a permissive policy
  would let any site the operator visits drive their local server).
  Serving the docs from both listeners keeps every call same-origin:
  open `/api-docs/` on `-addr` for the CAS + Xet Data API, or on
  `-hub-addr` for the Hub API. Both Hub landing pages now link it.
- **OpenAPI spec: `servers` is now a single relative `/` entry.** It was
  two hardcoded `http://localhost:842x` URLs, which aim the browser at
  those ports on the machine running the *browser* - correct only when
  that is also the server, and silently wrong for a remote host, a
  reverse proxy, or a non-default `-addr`. A relative URL resolves
  against whatever origin served the page, so "Try it out" targets the
  right server with no configuration. (An OpenAPI server-variable
  template was tried first and rejected: Swagger UI renders it as a
  literal placeholder with variable input boxes.)

### Fixed
- **`xet-proxyd` resolve HEAD followed the real Hub's redirect and dropped
  the Xet metadata.** Real HF answers a Xet file's resolve HEAD with a 302
  whose Location points at the CDN and whose headers carry `X-Xet-Hash`,
  `X-Linked-Size`, `X-Linked-Etag`; the proxy's `hfclient.Resolve` followed
  the redirect (Go's default) and read headers from the CDN's 200, which
  has none of them - so every download through the proxy 404'd with a
  `known=false` xet-hash lookup. Now it matches `huggingface_hub`
  (`allow_redirects=False`, `follow_relative_redirects=True`): same-origin
  (relative) redirects are followed, cross-origin ones are returned as-is,
  and the metadata is read from whichever response it lands on. Regression
  tests: `TestResolve_CrossOriginRedirectKeepsXetHeaders`,
  `TestResolve_FollowsSameOriginRedirect`.
- **`xet-proxyd` couldn't cache xorb bytes from the real HF CAS.** The
  real CAS server does not serve xorb bodies over `GET /v1/xorbs/` (its
  allow list is `HEAD,POST`); xorb bytes only come from the presigned CDN
  URLs in a reconstruction's `fetch_info`. The proxy's reconstruction
  cache path fetched `GET {casURL}/v1/xorbs/{hash}` (401 from the real
  CAS) instead. `ensureFileReconCached` now uses the reconstruction's
  `fetch_info` presigned URLs directly - fetching each covered byte range
  with the matching `Range` header, concatenating in ascending offset
  order, and ingesting the full xorb - and falls back to the direct
  `/v1/xorbs/` fetch only for upstreams that still serve xorbs that way
  (this project's own `xetd`, test stand-ins). See
  `docs/PROTOCOL.md` #12 for the full wire-format writeup.
- **The proxy's Hub/CAS write requests carried no `Content-Type`.** Real
  HF is FastAPI-based: a JSON/ndjson body without a matching `Content-Type`
  is not parsed at all, so create-repo failed with "expected string,
  received undefined" on its `name` field and preupload on
  `files[0].sample`. `hfclient` now sends `application/json` for
  create-repo/branch/preupload, `application/x-ndjson` for commit (matching
  `huggingface_hub`), and `application/octet-stream` for CAS xorb/shard
  uploads (per xet-core's `cas.openapi.yaml`).
- **`writeUpstreamError` reformatted upstream error bodies.** A real
  `huggingface_hub` client tolerating `exist_ok=True` reads the `url` field
  off create-repo's 409 response body; the proxy was relaying the status
  but writing its own `{"error": ...}` body, causing a `KeyError: 'url'`.
  It now relays the real upstream error body verbatim.
- **Preupload/commit were decode-and-reencoded, dropping required
  fields.** `hf upload`'s preupload body carries a per-file `sample` field
  and the commit body carries ndjson LFS-pointer lines; the proxy's
  decode-reencode dropped them. Both are now forwarded to the real Hub
  verbatim (parsing only a copy for the local ingest bookkeeping).
- **Small (non-Xet) file uploads 404'd against the proxy.** A file the Hub
  negotiates into Git LFS mode (`hf upload` of a small file) hits
  `/{repo}.git/info/lfs/objects/batch` and `/objects/...`; the proxy's
  resolve catch-all returned its own 404. Those paths are now relayed live
  to the real Hub.
- **A whole-repo download of a dataset with subdirectories 404'd on the
  first directory name** (`bigcode/the-stack-v2`, `404 Not Found` for
  `.../resolve/main/data`). `hf download` of a whole repo enumerates every
  path via `list_repo_tree(recursive=true)`, which interleaves real files
  with directory entries (`type: "directory"`, size 0). The proxy ingested
  every entry into its embedded `hubserver`, whose flat file model re-emits
  everything as `type: "file"` - so `snapshot_download` built a `RepoFile`
  for the top-level `data` folder and tried to resolve it as a file. `proxyhub`
  now drops non-file entries at tree-ingest time and in the `-no-cache`
  tree writer, so only real files are ever listed (and, downstream,
  downloaded). Regression tests: `TestListTree_DirectoryEntriesNotIngestedOrServedAsFiles`,
  `TestListTree_NoCacheFiltersOutDirectoryEntries`.
- **Resolve requests for non-Xet files 404'd against the proxy**
  (`bigcode/the-stack-v2`, `.../resolve/main/.gitattributes`). Small inline
  blobs (`README.md`, `.gitattributes`, `*_stats.csv`) carry no `X-Xet-Hash`,
  and the embedded `hubserver`'s resolve handler can only serve Xet files -
  it answers via CAS reconstruction data keyed by a Xet hash, and this
  proxy's SHA-256-to-Xet bridge reports "unknown" for everything else. The
  proxy relayed those resolves into a CAS-backed 404. `proxyhub.handleResolve`
  now detects a file with no upstream `X-Xet-Hash` and relays the real Hub's
  response live (the same transparent-relay path LFS traffic already used),
  without ingesting it - Embedded simply has nothing it can serve for it.
  Regression tests: `TestResolve_PlainFileHeadRelayedLiveNotIngested`,
  `TestResolve_PlainFileGetStreamsBytesLive`,
  `TestResolve_NoCachePlainFileRelayedLive`.
- **The new write-path relays could buffer unbounded request bodies.** The
  preupload/commit/LFS handlers read the request body to relay it verbatim;
  the commit handler had regressed from a 10 MB-bounded scanner to an
  unbounded read, and the LFS relay was new. All three now go through
  `readHubWriteBody`, which caps the body at 64 MiB (`http.MaxBytesReader`)
  and answers an oversize body with `413` before any upstream call -
  closing a memory-exhaustion vector and matching the upload caps
  `casserver`/`proxycas` already enforce. Regression test:
  `TestPreupload_OversizeBodyReturns413`.
- **`xet-proxyd`'s default CAS URL was malformed for an explicit
  `-addr`.** The default is built as `"http://localhost" + *addr`, which is
  correct for `-addr :8420` (`http://localhost:8420`) but mangled for
  `-addr 127.0.0.1:8420` (`http://localhost127.0.0.1:8420`), breaking the
  CAS URL handed to clients. Documented (see `docs/MIRRORING.md`): use the
  `:port` form, or pass `-cas-url` explicitly.
- **`fsstore` could fail reads on Windows during a concurrent upload's
  stage-then-rename.** On Windows a `os.Rename` transiently locks the
  destination path, so a concurrent `Get`/`GetRange` failed with
  ERROR_SHARING_VIOLATION and surfaced as a 500 (intermittently failing
  `TestChaos_ThunderingHerdOnColdKeyWithSlowUpstream`). `Get`/`GetRange`
  now retry `os.Open` briefly on that one transient Windows error; POSIX
  is unaffected (`rename(2)` is atomic).
- **The snapshot loop exhausted memory on any large cache, roughly once a
  minute.** `chunkHashToShard` stored the full shard body as *each
  chunk's* value. In memory every entry aliases one slice, but
  `encoding/json` has no notion of aliasing and re-emits the body per
  chunk: a ~30 MB shard covering ~1.7 M chunks serializes toward ~50 TB,
  and the process died with `fatal error: out of memory`. Shard bodies are
  now stored once, content-addressed, with chunks holding a 32-byte hash
  (`map[Hash]Hash` plus a shared `shardBodies` map), making snapshot size
  O(unique shards + chunks) rather than O(shards x chunks). Snapshot
  format bumped to **v2**.
- **`file_recon` was never persisted** - collateral damage from the above.
  While every snapshot attempt was dying, *nothing* was being
  checkpointed, so a data directory could look perfectly healthy (all xorb
  bytes present and correct) while a restarted server could not
  reconstruct a single file from it. Fixed by the snapshot fix and
  verified by confirming entries survive a restart.
- **A snapshot version mismatch is no longer fatal.** `LoadSnapshot` reads
  the `version` field first and, on mismatch, warns and starts with empty
  indices instead of returning an error - which would have meant a server
  refusing to start after any format bump until someone deleted the file
  by hand. Xorb bytes live in `storage.Store`, not the snapshot, so the
  only cost is re-deriving metadata as clients touch each repo again.
- **`maxShardBytes` raised 16 MB -> 512 MB** in both `casserver` and
  `proxycas`. The old bound assumed a shard covers roughly one xorb's
  worth of entries; a real multi-GB upload sends a single shard
  enumerating every chunk in the file, which is far larger, and uploads
  failed with `413 Request Entity Too Large`.
- **A reconstruction whose xorbs can't be cached no longer 502s.**
  `handleReconstructionCommon` now falls back to relaying upstream's
  reconstruction (logging at `WARN`) so the client still completes its
  download via the presigned URLs, instead of failing the request outright
  because the local cache couldn't be advanced.
- **`make build` produced an extensionless `bin/xetd` on Windows**, which
  the OS then could not execute - every downstream `./bin/xetd` reference
  (`make run`, `make integration-test`, `integrationTests.sh`) failed to
  find it. Output names now use `$(EXE)` from `go env GOEXE`.
- **The integration suite was not hermetic.** It inherited the developer's
  environment: an exported `HF_TOKEN` (very common, since `xetd`
  deliberately falls back to it) made the test's own server demand a token
  the tests never send, so the suite passed or failed depending on the
  machine. `integrationTests.sh` now clears `HF_TOKEN`,
  `XETD_AUTH_TOKEN`, `XET_PROXYD_AUTH_TOKEN` and `HF_ENDPOINT`;
  `auth_gated_access` is unaffected because it passes `-auth-token`
  explicitly to its own instance.
- **Windows path handling in the `hf` CLI tests.** `mktemp -d` yields a
  POSIX path; MSYS auto-converts bare path *arguments* but cannot convert
  one interpolated into a Python `-c` code string, so native Python
  received a literal `/tmp/...` and failed with `FileNotFoundError`.
  `RUN_ROOT` is now normalized via `cygpath -m` (a no-op off Windows), so
  every derived path works from both sides.
- **`xet_proxyd_offline_handoff` aborted silently on Windows.** Under
  `set -euo pipefail`, `wait` returns the *stopped process's* status; a
  graceful POSIX SIGTERM exits 0, but MSYS `kill` uses `TerminateProcess`
  and yields non-zero, killing the script before any assertion ran and
  printing nothing to explain it. Kill/wait are now tolerant, and
  snapshotting is platform-aware: POSIX keeps `-snapshot-interval 0` so
  the test still proves the graceful-shutdown snapshot specifically, while
  Windows uses a short interval and waits for the checkpoint.
- **Timeout diagnostics could never fire.** `if ! cmd; then status=$?`
  captures the *negated* status (always `0`), so the `-eq 124` check in
  both `hf` CLI tests was dead code and a genuine hang was reported as an
  unexplained generic failure. Six call sites now use `|| status=$?`.
  Per-command timeouts are also platform-aware (4s POSIX, 20s Windows),
  since `pipenv run` plus a cold interpreter start costs seconds before
  `hf` does any work.
- **`HF_XET_LOG_PATH=/dev/null` created a stray file on Windows.** Handed
  to a native `hf_xet`, that string is a literal path, not a discard
  device; the runner now exports `NUL` there and the tests defer to it.
- **Resolve paths with empty repo segments were accepted** (found by
  `FuzzParseResolvePath`). `//resolve//0` parsed to a repo ID of `/` -
  empty namespace *and* empty name, plus an empty revision - an identity
  no real request can address, which was then created as live server
  state and could be collided with by any similarly-malformed path. Both
  repo segments and the revision must now be non-empty; the LFS-batch
  endpoint applies the same check to its own extracted repo ID. Fixed in
  `hubserver` and `proxyhub`.
- **The LFS batch endpoint accepted trailing data after the JSON body**
  (found by `FuzzLFSBatchHandler`). `json.Decoder.Decode` reads the first
  value and silently ignores the rest, so `{"operation":"upload"}` plus
  arbitrary trailing bytes was treated as a well-formed batch. The body
  must now decode to exactly one JSON value. Lenient trailing-data
  handling is how two intermediaries end up disagreeing about what a
  request said.
- **The LFS batch endpoint was unbounded in three ways**, all of which it
  now rejects rather than truncates (truncating would leave the client
  believing files were negotiated that never were): an unbounded request
  body streamed straight into `json.Decode` (now `maxLFSBatchBytes`, 4 MB,
  via `http.MaxBytesReader`, reporting `413` instead of a misleading
  `400`); an unbounded object count, which mattered because the response
  *echoes* every object back and so turned a compact request into an
  amplification primitive (now `maxLFSBatchObjects`, 4096 - real clients
  batch 256); and repo state created *before* validation, letting a flood
  of malformed requests with random repo IDs grow the repo map without
  ever submitting a valid batch. See PROTOCOL.md section 13.1.

### Changed
- **Go module path**: `module xet-server` -> `module github.com/guilt/xet-server`
  in `go.mod`, with every internal import updated to match. Build/test
  behavior is identical; only the module identity and the docs-tool's
  string literals changed.
- **Release workflow artifacts**: platform artifacts are raw staging
  directories (not pre-zipped), and the final zips + `checksums.txt` are
  produced exactly once in the release job - avoiding GitHub's
  artifact-download zip-wrapping producing a zip-within-a-zip, and making
  the checksums reflect the exact zips attached to the release.

### Known limitations
- **Pull-through caching against the real Hub is partial, and this is
  structural rather than a bug to be fixed in the caching code.** A xorb
  is cached only when the fetched bytes can be verified against that
  xorb's content hash - storing them under a hash they don't match would
  corrupt the cache. But a reconstruction's `fetch_info` cites only the
  byte ranges *the requested file* needs, and because Xet deduplicates
  across repos a file routinely references xorbs written for other files,
  using only the chunks it shares with them (e.g. chunks 15-21 of a
  1042-chunk xorb). Those bytes cannot reproduce the whole xorb's hash,
  and the citation cannot be widened: the presigned URL is
  signature-scoped to exactly the cited range, and the real CAS does not
  serve xorb bodies over `GET /v1/xorbs/` (PROTOCOL.md section 12.2).
  Downloads still succeed via live relay - correctness and availability
  are preserved, only cache coverage is lost, and the proxy logs
  `WARN proxycas: reconstruction cache-ingest failed, falling back to live relay`.
  Caching such xorbs would require a different cache granularity (verified
  *chunk ranges* keyed by `(xorb, range)`), a larger change to the storage
  model. For a guaranteed-complete offline library, seed via the upload
  path instead - `hf_xet` chunks local files itself and always writes
  whole xorbs - as documented in MIRRORING.md section 10.

## [0.9.0] - 2026-09-11

The big one: `xet-proxyd`, a caching pull-through proxy in front of the
**real** huggingface.co - not primarily a performance cache, but an
offline-resilience layer. Point it at the real Hub, use it like any other
`HF_ENDPOINT`, and every repo/file it has successfully relayed once stays
servable via `hf download`/`hf upload` even after huggingface.co becomes
unreachable - including handing its cache directory to a plain `xetd` as
a permanent, disconnected replacement, with zero conversion step. Built
by embedding the exact same `casserver.Server`/`hubserver.Server` engines
`xetd` already runs, rather than a second, separately-maintained caching
implementation. Also: rate limiting and bounded timeouts across the whole
client/server stack, chaos tests for slow/hanging upstream behavior, a
manual lint pass (this sandbox's `staticcheck`/`golangci-lint` are both
broken against the pinned Go toolchain) that found and fixed several real
bugs, and a full documentation pass covering all of the above.

### Added
- **`cmd/xet-proxyd`**: the caching pull-through proxy binary, two ports
  mirroring `xetd`'s own `-addr`/`-hub-addr` split. `-upstream-hub-url`
  (falling back to `$HF_URL`, then the real huggingface.co) is the only
  new required concept; every other flag name/default matches `xetd`'s
  own where the same idea applies (`-data`, `-auth-token`,
  `-snapshot-interval`, `-rate-limit-rps`/`-rate-limit-burst`). New
  proxy-specific flags: `-no-cache` (pure-relay escape hatch, disabling
  all local caching and offline fallback), `-cache-ttl` (how long cached
  Hub metadata is served before attempting a live refresh; `-1` default
  means "always try live first"), `-metadata-call-timeout` (bounds a
  single repo-info/resolve/xet-token upstream call so a slow-but-not-dead
  real Hub doesn't hold up the fallback-to-cache path longer than
  necessary - never applied to tree listing, which pages internally
  within one call). `-addr`/`-hub-addr`/`-data` share `xetd`'s defaults,
  since this proxy is meant to be a drop-in alternative for the same two
  ports.
- **`internal/proxycas`/`internal/proxyhub`**: thin wrappers embedding a
  real `casserver.Server`/`hubserver.Server` as their serving engine.
  Each request either delegates straight to the embedded server (if it
  already has what's needed - checked via new `Has*` methods), or
  fetches from upstream via `internal/hfclient` and feeds the result into
  the embedded server via new `Ingest*` methods (`IngestXorb`,
  `IngestShard`, `IngestFileRecon`, `IngestRepoInfo`, `IngestFile`,
  `IngestCommit`) before delegating. **Any upstream failure - network
  error, timeout, 5xx - falls back to whatever's already cached, no
  matter how old** - this fallback rule is the whole reason the proxy
  exists; no separate retry-with-backoff logic was added on top of it,
  since it already reaches the correct outcome (a working `hf download`)
  as fast as possible. Writes (commit, preupload, repo/branch creation)
  are always relayed live with no fallback - only the real Hub can
  accept a real commit.
- **`internal/hfclient`**: the upstream HTTP client `xet-proxyd` uses to
  talk to the real Hub API (`Client`) and real Xet CAS (`CASClient`,
  whose base URL is discovered per-repo from a Hub xet-token response,
  never configured directly - matching how a real `hf_xet` client itself
  discovers it). Every call forwards the caller's own bearer token
  upstream completely unchanged (pure credential passthrough - this
  package never holds a secret of its own). `defaultHTTPClient` bounds
  connect/TLS-handshake/response-header latency (10s each) without a
  blanket request timeout, so a hung real huggingface.co fails fast
  without aborting a legitimately large, slow-but-progressing xorb
  transfer.
- **`internal/reconwire`**: the reconstruction wire types
  (`ResponseV1`/`ResponseV2`/`Term`/etc.) and response-building logic
  (`BuildV1`/`BuildV2`) extracted out of `casserver`, so this
  clipping/grouping logic has one independently-tested, fuzzed home
  rather than living only inline in `casserver`'s handlers. Bounds-checks
  every chunk-index field before indexing a footer's slices (a real,
  previously-reachable panic once untrusted upstream data - via
  `proxycas`'s ingest path - could reach it with an out-of-range index),
  returning a new `ErrChunkIndexOutOfRange` instead. Verified with a new
  fuzz target, `FuzzBuildV1_NeverPanics`.
- **Rate limiting on `xet-proxyd`, gating every route on both ports** -
  `-rate-limit-rps`/`-rate-limit-burst`, one `ratelimit.Limiter` shared
  across both ports so a client can't double its effective budget by
  splitting requests across them. Broader in scope than `xetd`'s own
  upload-only `-rate-limit-rps`: for a caching proxy, a cache-missing
  read costs a real outbound call to huggingface.co just as much as a
  write does. `internal/ratelimit.Limiter` also gained automatic pruning
  of fully-refilled-and-idle buckets (`pruneEvery`), so a long-running
  proxy fielding traffic from many distinct source IPs doesn't retain a
  bucket per IP forever.
- **Bounded execution under load across the whole stack**: HTTP servers
  (`xetd`, `xet-proxyd`) gained `ReadHeaderTimeout`/`IdleTimeout`; every
  HTTP client (`hfclient`, `internal/client`, `s3store`) gained a shared
  `defaultHTTPClient` with bounded connect/TLS-handshake/response-header
  phases but no blanket request timeout (so a legitimately large,
  slow-but-progressing transfer is never aborted early); `xet-proxyd`
  gained `-metadata-call-timeout` for single-shot Hub metadata calls; a
  real A->B->C consistency bug was fixed - both binaries previously only
  ever gracefully shut down their CAS-facing `http.Server`, leaving the
  Hub-facing one (when `-hub-addr` was set) killed abruptly with no
  connection draining, and `xet-proxyd`'s own shutdown timeout was too
  short to exceed what an in-flight handler blocked on a real slow
  upstream call could still legitimately be doing (raised from 10s to
  60s, with a comment explaining why `xetd`'s 10s remains correct for
  itself - its handlers only ever touch local storage).
- **Chaos tests for slow/hanging upstream behavior**
  (`internal/proxycas/chaos_test.go`, `internal/proxyhub/chaos_test.go`,
  `internal/hfclient/timeout_test.go`, `internal/proxyhub/timeout_test.go`):
  a fully-hung-before-headers upstream, a connected-but-frozen mid-body
  response, a connection reset mid-transfer, thundering-herd concurrent
  requests on a cold cache key, and - for `proxyhub` specifically - an
  upstream that's healthy for the first call and then dies, proving
  every subsequent request for the same resource still succeeds from
  cache rather than re-failing outright.
- **Landing pages + `/api-docs/` Swagger UI on `xet-proxyd`**
  (`landingpage.ProxyCASHandler`/`ProxyHubHandler`) - previously missing
  entirely; both ports now match `xetd`'s own "Xet Server"/"Xet Server -
  Hub API shim" title convention ("Xet Proxy Server"/"Xet Proxy Server -
  Hub API shim").
- **`integration-tests/xet_proxyd_offline_handoff.sh`**: the strongest
  proof this project has that `xet-proxyd` actually does what it claims.
  Drives the real `hf` CLI through a running proxy (relaying to a second,
  local `xetd` standing in for the real Hub, so this needs no network
  access) for an upload+download round-trip, gracefully shuts the proxy
  down, tears down its upstream entirely, starts a fresh plain `xetd`
  pointed at the proxy's own `-data` directory, and downloads the same
  file again with nothing else running - byte-identical. Wired into
  `integrationTests.sh` (now takes the built `xet-proxyd` binary as a
  required third positional argument, exported to test scripts as
  `$XET_PROXYD`) and `make integration-test`.
- **`docs/FAQ.md`**: why Xet's chunking/dedup model exists instead of
  plain S3/HTTP hosting, why this project exists, why `xet-proxyd`
  exists, and other questions worth answering once. Linked from the main
  README's Documentation section.
- **`docs/MIRRORING.md` #9** and a new "Caching pull-through proxy"
  section (with its own architecture diagram) in the main README and
  `docs/ARCHITECTURE.md`, covering `xet-proxyd` end-to-end: the offline-
  handoff story, the CAS-facing port's Hub-relay bootstrap requirement,
  and every new flag.
- **Acknowledgments** section in the main README (merged into the former
  "Related Projects" section), crediting xet-core/Hugging Face, zig-xet,
  `zeebo/blake3`, swagger-ui, and the Go tooling `scripts/build_docs.go`
  depends on.

### Fixed
- **A missing `shouldIgnore` field silently dropped on relay** -
  `hfclient.PreuploadResult` only had `Path`/`UploadMode`, so decoding a
  real Hub preupload response and re-serializing it through
  `proxyhub.handlePreupload` dropped `shouldIgnore` (and `oid`) entirely.
  Harmless against this project's own `hubserver` (which always sends
  `false`/omits `oid`), but crashed the **real** `hf` CLI with a
  `KeyError` the moment a real preupload response was relayed through
  the proxy - `huggingface_hub`'s `_fetch_upload_modes` reads
  `file["shouldIgnore"]` unconditionally, with no default. Found by
  `integration-tests/xet_proxyd_offline_handoff.sh` actually driving the
  real `hf` CLI through the proxy, not by any unit test - the existing
  `hfclient`/`proxyhub` preupload tests never asserted the field
  round-tripped at all. Fixed, and both a unit test
  (`TestPreupload_SendsFilesAndParsesResult`) and a dedicated regression
  test (`TestPreupload_RelaysShouldIgnoreFieldToRealHfClient`) now pin it.
- **`xet-proxyd`'s snapshot filenames didn't match `xetd`'s** -
  `proxycas-snapshot.json`/`proxyhub-snapshot.json` vs. `xetd`'s
  `casserver-snapshot.json`/`hubserver-snapshot.json`. Since
  `casSrv.Embedded`/`hubSrv.Embedded` are real `*casserver.Server`/
  `*hubserver.Server` instances producing the identical snapshot format
  either binary's own `Load`/`Snapshot` methods read and write, this
  silently defeated the entire "hand this proxy's `-data` directory to a
  plain `xetd`" design the program exists for - a plain `xetd` pointed at
  a proxy's data directory would find no snapshot at all and start with
  zero cached Hub metadata. Also: `xet-proxyd` was never snapshotting its
  Hub-facing cache at all (only the CAS-facing one), so even a same-binary
  restart would lose every cached repo/revision/file/resolve/xet-token
  entry. Both fixed together (filenames aligned, both servers now
  snapshotted on the same interval and on shutdown) - this is exactly
  what `xet_proxyd_offline_handoff.sh` above was written to catch, and it
  did, on its first real run.
- **`-no-cache` broke `xet-proxyd`'s CAS port permanently** -
  `proxyhub.handleXetToken` only recorded the real upstream CAS base URL
  (`casURLCache`) when `!s.NoCache`, but `UpstreamCASBaseURL()` (which the
  CAS-facing proxy needs for every single request) has nothing to do with
  per-response caching - it's routing state, learned once and needed
  forever after. Under `-no-cache`, this left the CAS-facing proxy
  permanently 503ing, contradicting `-no-cache`'s own documented behavior
  ("every request is relayed live"). Fixed: the CAS URL is now recorded
  unconditionally.
- **Two real correctness bugs found via a manual line-by-line review**
  (this sandbox's `staticcheck`/`golangci-lint` are both broken against
  the pinned Go 1.27.1 toolchain, so a background-agent-driven manual
  pass substituted for them): a ranged xorb fetch
  (`casserver.handleFetchXorb`) set `Content-Type`/`Content-Length`
  *after* calling `WriteHeader` for the `206` case, silently dropping
  `Content-Length` from every ranged response (Go snapshots headers at
  `WriteHeader` time); and `HEAD /v1/xorbs/{prefix}/{hash}` (both
  `casserver.handleHeadXorb` and `proxycas.handleHeadXorb`) skipped the
  prefix-validation check the sibling `GET` handler already enforced,
  letting a mismatched-prefix `HEAD` trigger a real upstream fetch+cache
  write it should have rejected with `400`. Both fixed with regression
  tests.
- **`proxycas.writeFetchError` collapsed every non-404 upstream failure
  to a blanket `502`**, including a `401`/`403` (the caller's own
  credential rejected by the real upstream) - inconsistent with
  `proxyhub.writeUpstreamError`'s identical-in-spirit policy of relaying
  the real upstream status for the same class of failure. Now relays any
  4xx as-is, reserving `502` for actual network/5xx faults.
- **An unbounded `io.ReadAll` on `proxycas.handleUploadXorb`'s request
  body** - unlike its sibling `handleUploadShard` (already capped via
  `http.MaxBytesReader`) and `casserver`'s own upload handler, a hostile
  client could force unbounded heap growth. Now capped at the same
  128 MiB `casserver` itself uses.

### Notes
- **Manual lint pass**: beyond the two fixes above, this pass also
  removed several genuinely dead code paths (`client.Client.Manifest`,
  `hubserver`'s unused `xetTokenType` parameter, `proxycas`'s unused
  `V1`/`V2` re-exports), fixed multiple stale doc comments describing a
  pre-refactor design, added logging to `proxycas`/`proxyhub` (previously
  silent on every 4xx/5xx, unlike every other server package in this
  project), and extracted a shared clipping loop out of
  `reconwire.BuildV1`/`BuildV2`'s near-duplicate bodies. See
  `internal/proxycas`, `internal/proxyhub`, `internal/hubserver`,
  `internal/client`, `internal/reconwire`, `internal/ratelimit` for the
  full diffs.
- **`GO_VERSION` in the `Makefile` was stale** (`1.21`, when `go.mod`
  requires `1.27.1` and has for several releases) - corrected to `1.27`;
  README's Prerequisites updated to match.
- **`make run-proxy`** added, mirroring `make run`'s convenience for
  `xetd`.

## [0.8.0] - 2026-09-08

Closes this project's one remaining deliberately-deferred gap from v0.7.0:
authentication. Pluggable AuthN/AuthZ across every HTTP surface this
project exposes (the real Xet CAS protocol, the Hub API shim, and the Xet
Data API), a matching client-side credential interface, and a
`-auth-token`/environment-variable convention mirroring how the real `hf`
CLI is configured - while keeping every pre-v0.8.0 deployment's behavior
completely unchanged unless the new flag/env var is actually used. Also
adds interactive API docs, a consistent URL versioning scheme across every
server, and landing pages for both `xetd` ports.

### Added
- **`internal/auth`**: `Authenticator`/`Principal` (server-side AuthN/AuthZ)
  and `CredentialHelper` (client-side credential attachment) as small,
  independently implementable interfaces - mirroring the shape of real
  xet-core's own `xet_client::common::auth::CredentialHelper` trait.
  Ships two built-in implementations of each: `NoAuth`/`NoopCredentialHelper`
  (the zero-config default - no enforcement, no credential sent, byte-for-
  byte this project's pre-v0.8.0 behavior) and `StaticTokenAuth`/
  `BearerCredentialHelper` (a single shared bearer token, compared with
  `crypto/subtle.ConstantTimeCompare`, RFC 6750 case-insensitive scheme
  matching). A third-party implementation of either interface works with
  both `xetd` and `xet` unmodified - no changes to `casserver`, `hubserver`,
  or `internal/api` required.
- **Scope enforcement on every route** across `casserver` (CAS protocol,
  `/v1`, `/v2`), `hubserver` (Hub API shim), and `internal/api` (Xet Data
  API): write scope for uploads/commits/preupload/repo-create, read scope
  for downloads/reconstructions/resolve/chunk-dedup lookups. Unauthenticated
  requests get `401`; authenticated-but-insufficient-scope requests get
  `403`. Each server's own operator/health endpoints (telemetry,
  storage-stats, Xet Data's `stats`) are deliberately never gated, matching
  how these aren't part of any real protocol to begin with.
- **`xetd -auth-token <secret>`** (default `"None"`, disabling enforcement)
  and **`xet -auth-token <secret>`** on `push`/`pull`/`stats`, wiring
  `StaticTokenAuth`/`BearerCredentialHelper` into every server/client
  constructed by these binaries.
- **Environment variable fallback**, preferred over the flag on any
  shared/multi-user machine since flag values leak via `ps`/shell history
  in a way environment variables do not: `xetd` falls back to
  `$XETD_AUTH_TOKEN`, then `$HF_TOKEN`; `xet` falls back to
  `$XET_AUTH_TOKEN`, then `$HF_TOKEN` (the same variable the real `hf` CLI
  reads, so an already-exported `HF_TOKEN` "just works" against this
  server, on both the client and server side, with no separate secret to
  configure). An explicit `-auth-token` flag always wins over either
  variable. The precedence rule and the bearer-token-extraction logic
  behind it are both exported from `internal/auth`
  (`auth.ResolveToken`/`auth.BearerToken`) - the same primitives a future
  relay/proxy in front of the real huggingface.co Xet backend would use to
  resolve its own upstream credential, or to forward a caller's token
  upstream unchanged.
- **`internal/api`'s routes now share the `/v1` namespace with the CAS
  protocol** (`upload`, `files/{id}`, `files/{id}/manifest`, `stats`)
  instead of living unprefixed at the server root (`/upload`,
  `/files/{id}`, `/stats`) - matching `casserver`'s own `/v1`,`/v2`
  convention instead of being the one unversioned surface on the same
  process; the two APIs' literal paths never collide (`casserver`'s own
  `/v1` routes are `xorbs`, `shards`, `reconstructions`, `chunks`,
  `telemetry`, `storage-stats`). `internal/client.Client` and every
  integration test were updated to match; this is a breaking path change
  for this API only (not the wire-compatible CAS/Hub protocols, which are
  untouched since real clients depend on their exact paths).
- **`internal/routing`**: `Mount`/`MountWithVersion`/`Apply` - every
  server's route table (`casserver`, `internal/api`, `hubserver`,
  `cmd/xetd`'s own top-level mux) is now built as one declarative
  `[]routing.Route` list instead of a sequence of individual
  `mux.Handle`/`HandleFunc` calls. Paired with exported path constants on
  each server (`casserver.V1`/`.XorbsPath`/`.ShardsPath`/etc.,
  `api.V1`/`.UploadPath`/`.FilesPrefix`/`.StatsPath`) so every version
  prefix and literal path has exactly one definition, referenced by
  `cmd/xetd`'s mux wiring, `internal/landingpage`'s endpoint tables, and
  `internal/client`'s request-URL building - no path segment is
  hand-typed as a duplicate string literal anywhere outside the
  constant's own declaration.
- **`internal/apidocs/openapi.yaml`**: a hand-authored, source-verified
  OpenAPI 3.0 spec covering every endpoint across `casserver`,
  `hubserver`, and `internal/api`, including the auth model. Served
  through a fully offline Swagger UI at `/api-docs/` on the CAS server's
  address - no CDN dependency, since both the spec and the vendored
  Swagger UI static assets (`third_party/swagger-ui-dist`) are compiled
  into the `xetd` binary via `go:embed` (see `internal/apidocs`).
- **`internal/landingpage`**: opening `xetd`'s CAS port or Hub shim port
  directly in a browser (e.g. `http://localhost:8420/`) now renders a
  short HTML page listing that port's endpoints and a quick-start example,
  instead of falling through to whatever handler used to own the bare `/`
  route. On the Hub shim port, implemented as a thin wrapper that
  intercepts only an exact `GET /` (not a second `http.ServeMux`, which
  would have let `HEAD /` silently fall back to the landing page's `GET`
  handler and swallow real resolve-path traffic - caught by a regression
  test before it shipped).
- **`xet -server` is now genuinely optional**, falling back to
  `$XET_SERVER`, then `http://localhost:8420` - matching `-auth-token`'s
  own flag/env/default precedence exactly. (It always had a default value
  in practice; only the usage text and flag description wrongly implied
  it was required, and there was no environment-variable override.)
- **`docs/MIRRORING.md`**: a practical, copy-pasteable guide to
  self-hosting a real model mirror with this server - starting it,
  securing it with `-auth-token`, pointing the real `hf` CLI at it, and
  uploading/downloading whole repos or single files. Every command in it
  was run against a live server while writing it, which is what surfaced
  the whole-repo-download gap fixed below.

### Fixed
- **`internal/api` (the Xet Data API) had no auth wiring at all** -
  `-auth-token`/the client-side credential helpers had no effect on
  `xet push`/`pull`/`stats`, since those commands talk to `/v1/upload`,
  `/v1/files`, `/v1/stats`, not the CAS protocol's own `/v1` routes.
  `internal/api.Server` now has the same `SetAuthenticator`/`requireScope`
  pattern as `casserver`: write scope for `upload`, read scope for
  `files/{id}` and its manifest, `stats` left unauthenticated (an
  operator endpoint, not part of any real protocol).
- **`hubserver`'s `POST /api/repos/create` route bypassed scope
  enforcement entirely.** It was registered as its own literal
  `http.ServeMux` pattern, which Go's mux matches in preference to the
  wildcard `POST /api/{rest...}` pattern that carries the actual
  `requireScope` check - so the scope check inside `handleAPIPost`'s
  `rest == "repos/create"` branch was unreachable dead code. Repo creation
  is now dispatched through `handleAPIPost` like every other `/api/`
  route, with no separate literal registration.
- **`hf download REPO_ID` (whole repo, no filename) 404'd** - discovered
  while writing `docs/MIRRORING.md` by actually running the command
  against a live server rather than assuming it worked because
  single-file download already did. `huggingface_hub`'s
  `snapshot_download` (what a filename-less `hf download` uses) calls two
  endpoints neither `hubserver` implemented at all:
  `GET .../revision/{revision}` (resolve a revision before listing files)
  and `GET .../tree/{revision}` (enumerate every file in one call,
  recursively). Both are now implemented (`internal/hubserver/repo.go`,
  `tree.go`), verified against the real installed `huggingface_hub`
  package's source (not the public docs) for the exact URL templates and
  JSON field names expected.
- **`hf upload ... --revision <new-branch-name>` fatally errored instead
  of creating the branch** - found while fixing the gap above:
  `hf upload`'s CLI command checks whether a revision exists via the same
  `GET .../revision/{revision}` endpoint, expecting a `RevisionNotFound`
  error it specifically catches (via an `X-Error-Code` response header,
  not the status code alone) before calling `POST .../branch/{branch}` to
  create it - this shim returned a plain `404` with no header, which
  `huggingface_hub` doesn't map to that specific exception, so it
  propagated as a fatal error instead of triggering branch creation. Both
  the header and the missing branch-creation endpoint are now
  implemented.
- **The three new hubserver endpoints above weren't reflected in
  `internal/apidocs/openapi.yaml` or either landing page's endpoint
  table** - caught in review right after implementing them, before this
  release shipped with docs already stale on day one. Both are now
  updated and cross-checked live against a running server's `/api-docs/`.

## [0.7.0] - 2026-09-08

A protocol-completeness release: every gap this project's own "Where this
diverges from real Xet" list called out has been closed except
authentication (explicitly deferred to a future version). This is also
the first release with restart-surviving state - previously, an `xetd`
restart lost all reconstruction/repo metadata even though bulk chunk
data was always durable in the storage backend.

### Added
- **Optional dedup-hit content verification** (`internal/storage`'s new
  `VerifyingStore`, enabled via `xetd -verify-dedup`). On a dedup hit
  (`Put` for a content hash that already exists), instead of trusting
  the hash alone, byte-compares the incoming upload against the stored
  blob concurrently in fixed-size chunks, bailing at the first mismatch
  rather than reading either side in full. A mismatch - a hash collision
  or undetected storage-layer corruption - returns a new
  `storage.ErrContentMismatch` sentinel and refuses the write (the
  original stored blob is never overwritten), logged at `Error` via
  `casserver` so it's distinguishable from routine request failures.
  Off by default: benchmarked at roughly 10x slower than the default
  trust-the-hash path on a dedup hit (a full extra read), and mismatch
  detection is confirmed to scale with where the mismatch actually is
  (a mismatch 1% into a 16 MiB object is caught ~16x faster than one at
  99%) rather than always paying full-object comparison cost. Required
  adding `merklehash.Hash.MarshalText`/`UnmarshalText` so `Hash` can be
  used as a JSON map key at all (a prerequisite for this release's
  persistence work too, not just this feature).
- **Real revisions/branches in the Hub API shim.** `hubserver.repoState`
  now holds a map of independent `revisionState`s (each with its own file
  set and commit history) instead of one implicit `main`; a `main`
  revision is still created automatically on repo creation (matching a
  real repo always having a default branch), and any other revision name
  is created on first commit to it, mirroring how pushing to a new branch
  name creates it on a real repo. Committing the same file path to two
  different revisions now correctly produces two independent Xet-hash/
  size mappings, confirmed by `TestRevisions_IndependentFileSetsPerRevision`.
- **A real global chunk-dedup index.** `GET /v1/chunks/{prefix}/{hash}`
  previously always returned `404`. The real wire contract (confirmed
  against xet-core's actual client source - see docs/PROTOCOL.md #9) is
  to return the raw bytes of whichever previously-uploaded shard
  referenced the queried chunk hash, which the client parses itself to
  discover every dedup-eligible chunk in that shard, not just the one it
  asked about. `casserver.handleUploadShard` now indexes every chunk hash
  referenced by an uploaded shard's xorb-info section against that
  shard's raw bytes; a query for a known chunk hash returns those bytes
  verbatim.
- **Real V2 (multi-range) reconstruction.** `GET /v2/reconstructions/{file_id}`
  previously always returned `501`. It now returns xet-core's actual
  `QueryReconstructionResponseV2` shape (confirmed against xet-core's own
  struct definitions and its `update_260316_v2_reconstruction_multirange.md`
  changelog): the same underlying terms and physical byte ranges as V1,
  grouped by xorb hash into one `XorbMultiRangeFetch` entry (one URL,
  multiple chunk/byte ranges) instead of V1's one `fetch_info` entry per
  term. `TestReconstructionV2_MatchesV1Data` cross-checks V1 and V2
  responses for the same file and asserts identical underlying data. See
  docs/PROTOCOL.md #10 for why this is a response-shape optimization, not
  new reconstruction logic.
- **Restart-surviving persistence for in-memory metadata.**
  `casserver.Server` and `hubserver.Server` both gained
  `Snapshot(path)`/`LoadSnapshot(path)`: a periodic (default 1 minute,
  `-snapshot-interval`) and shutdown-time (`SIGINT`/`SIGTERM`, handled via
  `signal.NotifyContext` in `cmd/xetd/main.go`) atomic JSON checkpoint of
  every in-memory index, using the same stage-to-temp-then-rename pattern
  `storage/fsstore.Store.Put` already relies on so a reader never
  observes a half-written snapshot. Deliberately a periodic checkpoint,
  not a write-ahead log - writes between checkpoints are lost on an
  *un*graceful process termination (a crash, `kill -9`, power loss), not
  just preserved-until-clean-exit; see docs/PROTOCOL.md #11 for the full
  tradeoff writeup and why this was chosen over a WAL for this project.
  Verified with a real end-to-end round-trip: `hf upload` against a live
  server, a process restart against the same `-data` directory, then a
  real `hf download` of the same file from the fresh process producing a
  byte-identical file with zero re-upload.

### Changed
- README's "Where this diverges from real Xet" section now lists only
  authentication - every other previously-tracked gap (revisions,
  V2 reconstruction, global chunk-dedup, restart persistence) is closed
  as of this release.


storage layer, driven by "how do we know this is actually safe against a
hostile or merely broken client" rather than a new feature - specifically
including whether the dedup fast-path itself could be cheaply starved or
bypassed. Found and fixed four real bugs, two of them genuine
remotely-triggerable DoS vectors, plus added the test infrastructure
(native Go fuzzers, adversarial HTTP payload tests, chaos/concurrency
tests, benchmarks) to keep catching this class of issue going forward.

### Fixed
- **LZ4 decompression-amplification denial-of-service - the more severe
  of the two DoS findings, and the direct answer to "can dedup itself be
  attacked":** `decompressBlockUnknownSize` regrew its output buffer by
  doubling with no ceiling whenever decompression exceeded the current
  buffer. LZ4's block format lets a single match-length extension sequence
  (a run of `0xFF` bytes, each worth +255 to the match length) expand to
  hundreds of times its compressed size. **Empirically confirmed**: a
  ~16 MiB compressed chunk - well within a single chunk's 24-bit
  `CompressedLength` field, and far under `casserver`'s 128 MiB
  whole-upload cap - decompressed to **3.8 GB and took ~8 seconds** on
  ordinary hardware. Critically, this cost is paid on *every* upload
  attempt of the same malicious xorb: a chunk's hash can't be verified
  (and therefore can't be deduplicated against) without first
  decompressing it, so **the dedup fast-path provides no mitigation for
  this attack shape** - investigated specifically in response to the
  question of whether dedup itself opens a cheaper DoS path. Fixed by
  treating the LZ4 frame descriptor's declared max-block-size code as a
  hard decompression ceiling rather than merely an initial sizing guess -
  a real, spec-compliant encoder never produces a block exceeding it, so
  rejecting one that does can only ever reject a malformed or hostile
  frame, never a legitimate one. See `docs/PROTOCOL.md` #7 and
  `internal/lz4/dos_test.go`.
- **Allocation-size denial-of-service in shard/xorb parsing.**
  `shardformat.ReadFileLookupTable`/`ReadXorbLookupTable`/
  `ReadChunkLookupTable` and `readFileInfoSection`/`readXorbInfoSection`
  allocated `make([]T, numEntries)` directly from an attacker-controlled
  wire field (`FileDataSequenceHeader.NumEntries`,
  `XorbChunkSequenceHeader.NumEntries`, and the footer's lookup-table entry
  counts), with no bound against how many bytes were actually available to
  read. **Empirically confirmed**: a 96-byte malicious shard body claiming
  `NumEntries = 0xFFFFFFFF`, posted to `POST /v1/shards` (no auth
  required, well under the existing 16 MiB `maxShardBytes` cap), forced a
  single allocation request of **206,158,505,008 bytes (~192 GiB)** - an
  instant crash on any real machine. `xorbformat.ParseFooterV1`'s three
  `numChunks`-sized allocations had the identical shape (not currently
  reachable via any HTTP path, since real clients upload xorbs without a
  footer - see PROTOCOL.md #2 - but fixed anyway since it parses
  untrusted-shaped data). Fixed by switching every site to incremental
  `append`-based growth capped at a small preallocation ceiling
  (`maxLookupEntryPreallocate`/`maxSectionEntryPreallocate`/
  `maxFooterEntryPreallocate`, 4096 entries): a claim of billions of
  entries now fails fast on the first genuinely-missing byte instead of
  attempting the allocation upfront, while a legitimately large, honest
  shard/footer still parses correctly via `append`'s normal growth.
  Regression tests in `internal/shardformat/dos_test.go` reproduce the
  exact malicious payload and assert it fails within 5 seconds without
  attempting more than 64 MiB of heap growth.
- **Concurrent uploads of the same content could spuriously fail.**
  `fsstore.Put`'s staging temp file was named `<path>.tmp-<pid>` - every
  concurrent `Put` call for the *same key* within one process (e.g. several
  clients uploading an identical xorb at once) collided on that exact
  path, and `O_EXCL` correctly rejected the collision with `EEXIST`,
  surfacing as a `500` to every request but one. This is a normal,
  expected race for a content-addressed store (concurrent duplicate
  uploads should all succeed via dedup, not serialize on a filename
  accident) - found by
  `TestAdversarial_ConcurrentUploadsOfSameXorb` firing 20 concurrent
  uploads of one xorb and observing only 1 succeed. Fixed by using
  `os.CreateTemp` (a unique random suffix per call) instead of a
  PID-based name, plus treating a losing `os.Rename` race as a successful
  dedup (not a failure) as long as the target path exists afterward.
- **`fsstore.TotalBytes` (backing the eviction sweep's storage-budget
  check) could abort entirely on an ordinary concurrent race.** Found by
  `TestChaos_UploadFetchEvictInterleaved` running uploads, fetches, and an
  eviction sweep concurrently: `filepath.WalkDir` visiting a path that a
  concurrent `Put`'s rename or a concurrent `Delete` had just removed
  returned `os.ErrNotExist`, which the walk callback treated as a fatal
  error, aborting the *entire* measurement rather than just skipping that
  one now-vanished entry. Fixed to treat a disappearing file/directory as
  "not there anymore, don't count it" rather than a walk failure.
  Separately, in-flight upload staging files (`.tmp-*`) were being counted
  toward the budget at all - inflating it with uploads that hadn't
  committed and might never complete - and a staging file orphaned by a
  crashed process (never reaching its own cleanup) would then be silently
  excluded *forever*, a permanent disk-space leak hidden from the count.
  Fixed: a temp file younger than 30 minutes is excluded (presumed
  legitimately in-flight); one older than that is treated as orphaned and
  actually removed, so disk space is reclaimed rather than just hidden.

### Added
- **Native Go fuzz tests** (`go test -fuzz`) for every binary/wire parser
  reachable with attacker-controlled bytes: `merklehash.FromHex`/
  `FromRawBytes`, `lz4.DecompressFrame`/`DecompressBlock`, `bg4.Reverse`,
  `xorbformat.ReadChunkHeader`/`ScanChunks`/`ParseFooterV1`,
  `shardformat.ReadShard`, and `casserver.parseByteRange`. Seeded with
  valid round-tripped encodings (including the real `hf_xet`-captured
  fixtures already in `testdata/`) plus hand-picked edge cases. Each ran
  clean (zero crashes/hangs/OOMs) across tens of millions of executions
  combined during this pass - see `*/fuzz_test.go`.
- **Adversarial HTTP payload tests** (`*/adversarial_test.go`): malformed
  xorb/shard bodies, hostile hash/path/filename segments (path traversal,
  SQL-injection shapes, null bytes, oversized ndjson lines), malformed
  `Range` headers, `Content-Length` lies, and a concurrent-duplicate-upload
  stress test - each asserting both a clean error response *and* that the
  server keeps serving correctly afterward, not just "didn't crash on this
  one request."
- **Chaos/reliability tests** (`internal/casserver/chaos_test.go`): an
  upload interrupted mid-body followed by a clean retry (proving
  `fsstore.Put`'s atomic-rename staging leaves no corruption for the retry
  to inherit), sustained concurrent traffic mixing valid and malformed
  requests (proving malformed traffic never corrupts or drops unrelated
  valid state), and upload/fetch/eviction-sweep interleaving under a tight
  storage budget (proving no deadlock and no corruption of anything the
  sweep didn't evict).
- **Benchmarks** (`*/benchmark_test.go`, `go test -bench`): chunking
  throughput (`internal/chunk`), BLAKE3-keyed hashing and Merkle
  aggregation (`internal/merklehash`), LZ4 frame decompression
  (`internal/lz4`, including against the real captured fixture),
  ByteGrouping4 reverse transform (`internal/bg4`), and a dedup-speed
  benchmark (`internal/api`) quantifying the actual wall-clock advantage of
  deduplication: a fully-duplicate 16 MB upload runs at **~250 MB/s**
  versus **~74 MB/s** for entirely unique content of the same size - a
  **~3.4x** throughput difference from skipping storage I/O on the dedup
  fast path (chunking/hashing cost is paid either way).

## [0.5.0] - 2026-09-07

Defense-in-depth follow-up to 0.4.0's performance work: bounded, observable
storage eviction and per-client upload rate limiting - both scoped as
measurable, single-node policies rather than open-ended hardening.

### Added
- **Storage auto-pruning** (`internal/eviction`): an optional background
  sweep (`xetd -max-storage-bytes N -eviction-interval 5m`) that evicts
  least-recently-accessed xorbs once total storage exceeds the configured
  budget. Never evicts a xorb with a fetch currently in progress
  (`casserver.Server` tracks per-xorb in-flight fetch counts); every
  eviction is logged at `Info` with key, reason, and bytes freed. Disabled
  by default (`-max-storage-bytes 0`).
  - `storage.Deleter` and `storage.Sizer` are new optional capability
    interfaces (matching the existing `storage.URLPresigner` pattern),
    implemented by both `fsstore` (directory walk / `os.Remove`) and
    `s3store` (paginated `ListObjectsV2` / `DELETE`).
  - `GET /v1/storage-stats` (operator-facing, not part of the real Xet CAS
    API) reports whether eviction is enabled and, if so, the configured
    budget plus cumulative evictions/bytes freed - so the policy's effect
    is directly observable on a running server, not just inferable from
    logs.
- **Per-source-IP upload rate limiting** (`internal/ratelimit`): a
  hand-rolled token-bucket limiter (no new dependency) gating the xorb and
  shard upload endpoints specifically - the expensive paths (chunk
  decompression, hashing) a client hammering the server would otherwise
  cost the most. Configurable via `xetd -rate-limit-rps N
  -rate-limit-burst N`; disabled by default. Exceeding the limit returns
  `429 Too Many Requests` with a `Retry-After` header, logged at `Debug`
  (a retrying client backing off is expected behavior, not a fault).
  Fetch/reconstruction/HEAD endpoints are deliberately not rate-limited.

### Notes
- Both features are single-node, in-memory policies with no cross-restart
  persistence (eviction's LRU state resets on restart; rate-limit buckets
  are per-process) - consistent with the rest of this server's existing
  persistence model (see README's "Where this diverges from real Xet").
  Auth-based (rather than IP-based) rate limiting is out of scope until
  this server has an auth model at all.

## [0.4.0] - 2026-09-05

### Added
- Sentinel storage errors `storage.ErrNotFound` and `storage.ErrSizeMismatch`
  (`errors.Is`-checkable), returned consistently by both `fsstore` and
  `s3store` instead of backend-specific ad hoc errors - a caller no longer
  needs to know which backend it's talking to to detect "not found" vs. a
  real fault.
- `casserver`'s xorb and shard upload handlers now cap request body size
  (`http.MaxBytesReader`, 128 MiB for xorbs - well above real xet-core's
  ~64 MiB per-xorb target, 16 MiB for shards - metadata bounded by chunk
  count, not file size) and return `413 Request Entity Too Large` instead
  of allowing an unbounded read.
- `log/slog` is now used consistently for all runtime logging across
  `casserver`, `hubserver`, and `cmd/xetd` (previously a mix of `log.Printf`
  and `slog.Debug`). 4xx responses (client protocol/input errors - a bad
  hash, a truncated upload) log at `Debug`; 5xx responses (server-side
  faults) log at `Warn`; startup/lifecycle events log at `Info`. `log.Fatal`
  remains for unrecoverable startup errors in `cmd/xetd`, since `slog` has
  no equivalent terminate-and-exit call.

### Changed
- **`storage.Store` is now streaming.** `Put(ctx, key, data []byte)` became
  `Put(ctx, key, r io.Reader, size int64)`; `Get`/`GetRange` now return
  `io.ReadCloser` instead of `[]byte`. Neither `fsstore` nor `s3store` ever
  buffers a full xorb in memory anymore - a multi-gigabyte upload/download
  now costs a fixed, small amount of memory regardless of file size,
  verified end-to-end with real GGUF model files up to 27.6 GB
  (`~/.ollama/models/blobs`) round-tripped byte-identical through the
  actual `hf` CLI, and unit-benchmarked at ~500-575 MB/s sustained write
  throughput to a local filesystem store.
  - `fsstore.Put` stages each write to a per-attempt temp file and only
    renames it into place once the full declared size has been copied -
    a failed, canceled, or short read leaves no partial blob visible under
    the key, and the caller can simply retry with a fresh reader.
  - `casserver.handleUploadXorb` streams the request body to a temp file
    (`xorbformat.ScanChunks` needs `io.Seeker`, which an `http.Request.Body`
    doesn't support) and only hands it to the storage backend once the
    whole body is received and its claimed hash verified - a client that
    disconnects mid-upload never leaves a partial xorb stored.
  - `s3store.Put` signs with `sigv4.UnsignedPayload` instead of a
    precomputed SHA-256 content hash, since computing that hash would
    require buffering the whole body up front, defeating the point of
    streaming a multi-GB xorb.
- **`casserver.Server`'s single global `sync.RWMutex` is now three
  independent locks** (`fileReconMu`, `xorbMu`, `sha256Mu`), one per index
  map. No code path ever needed a consistent snapshot across more than one
  map, so the shared lock only serialized unrelated concurrent
  uploads/downloads without buying any real consistency guarantee - a large
  xorb upload (touching only `xorbFooters`/`xorbRawLength`) can now proceed
  concurrently with an unrelated reconstruction lookup (touching only
  `fileRecon`).
- **`hubserver.Server`'s single global mutex now only guards the top-level
  `repos` map**; each `repoState` has its own mutex for its files and commit
  metadata, so a commit or resolve request against one repo no longer
  blocks on unrelated activity in a different repo.

### Fixed
- `handleUploadXorb` seeks its staging temp file back to the start before
  scanning chunk headers - a regression introduced while switching from
  `bytes.NewReader` (which was implicitly at the correct offset) to a
  temp file (left at EOF after `io.Copy` from the request body), caught by
  the existing xorb-upload regression tests before it shipped.
- `hubserver.resolve.go`'s `commitOIDOrPlaceholder` read `repoState.commitOID`
  /`commitSeen` without holding `repoState`'s mutex - a pre-existing data
  race, now fixed as part of introducing per-repo locking. Confirmed the
  full test suite (unit + integration) passes clean under `go test -race`.

## [0.3.0] - 2026-09-04

### Added
- `Pipfile`/`Pipfile.lock` and `make install`/`make install-deps` to manage
  the optional `huggingface_hub`/`hf_xet` dependencies for
  `hf_cli_roundtrip.sh` via `pipenv`, instead of a hand-rolled venv.
- `scripts/build_docs.go`: a self-contained Go program (own module,
  `scripts/go.mod`) that regenerates `docs/godoc/*.md` via `go doc -all`
  and renders all Markdown docs to browsable HTML in `docs/build/`, using
  `goldmark` (GFM/tables/TOC anchors), `chroma` (pygments-equivalent
  syntax highlighting), and `goldmark-mermaid` (Mermaid diagram
  rendering via `merman-cli` or `mmdc`, whichever is available and
  functional, with a styled source + mermaid.live-link fallback
  otherwise). `make docs`/`make docs-serve` now just run this program;
  `make pre-check` reports which Mermaid renderer (if any) is available.
- `.env`/`.env.example` support in the `Makefile` (`PIPENV_PYPI_MIRROR`,
  for networks that can't reach `pypi.org` directly) - read by `make
  install` via `include .env` + `export`, gitignored, never committed.
- `DEBUG=1` environment variable for `cmd/xetd`: enables `log/slog` debug
  logging of every HTTP request (method, path, status, duration) plus
  commit/shard/resolve lookup details in `hubserver`/`casserver`. This is
  what surfaced both real bugs fixed below.

### Changed
- Integration test default timeout lowered from 60s to 10s
  (`XET_IT_TEST_TIMEOUT`); `hf_cli_roundtrip.sh` now also wraps each `hf`
  invocation in its own tighter internal timeout (`XET_HF_CLI_CMD_TIMEOUT`,
  default 4s) so a proxy-hang fails fast instead of consuming the outer
  budget. The full suite (5 fast tests + the hf CLI test failing/skipping)
  now completes in well under 10 seconds.

### Removed
- `scripts/build_docs.py` and `scripts/gen-docs.sh` (Python/pipenv +
  bash), replaced by `scripts/build_docs.go`. `markdown`/`pygments`
  dropped from `Pipfile`'s dev-packages - pipenv is now only needed for
  the optional `hf` CLI integration test, not docs.

### Fixed
- `GET /api/{repo_type}s/{repo_id}/xet-{read,write}-token/{revision}`
  (the Hub API shim) returned the CAS URL/access token only as
  `X-Xet-*` response headers with an empty body. Real `hf_xet` clients
  decode this response as a **JSON body**
  (`DirectRefreshRouteTokenRefresher::get_cas_jwt` in xet-core, deserializing
  into `CasJWTInfo{casUrl, exp, accessToken}`) - an empty body fails that
  decode, which `hf_xet` treats as a transient error and retries
  indefinitely instead of failing fast, so `hf upload` just hung past any
  timeout. Now returns the JSON body in addition to the headers (the
  latter still used by `huggingface_hub`'s resolve/download metadata
  path). See [docs/PROTOCOL.md](docs/PROTOCOL.md) #6.
- `casserver.handleUploadShard`'s `sha256ToXet` index (bridging a
  committed file's plain SHA-256 to its Xet/Merkle hash for downloads)
  was keyed by a raw hex encode of `FileMetadataExt.SHA256`'s wire
  bytes. Real `hf_xet` clients write that field through the same
  word-reversal byte-order transform as a genuine Merkle hash's `Hex()`
  - confirmed by capturing a real upload and comparing the raw bytes
  against the file's actual SHA-256 in the commit payload's
  `lfsFile.oid`. The raw-byte encoding never matched, so every
  `hf download` 404'd once uploads stopped hanging (previous bug). Fixed
  to use `.Hex()`. See [docs/PROTOCOL.md](docs/PROTOCOL.md) #1/#3.
- The Mermaid diagram fallback link (shown when no working Mermaid
  renderer is available) pointed to a `mermaid.live/edit#pako:` fragment
  built from a plain URL-encoded diagram source; mermaid.live actually
  expects that fragment to be a zlib-deflated, base64url-encoded JSON
  envelope (`{"code": ..., "mermaid": {...}}`), so the link never
  decoded. Fixed to build the correct payload.
- `docs/ARCHITECTURE.md`'s CAS-upload sequence diagram used `->` and a
  stray `;` inside a `Note over` line, which some Mermaid parsers
  (including `merman-cli`) reject - replaced with plain ASCII.
- `make help` (and any target output listing `$(MAKEFILE_LIST)`) printed
  `Makefile` as every target's name instead of the real target, once
  `.env` was added to `MAKEFILE_LIST` via `include` - `grep -E` prefixes
  matches with the source filename when searching more than one file,
  which shifted `awk`'s field split. Fixed with `grep -hE`.

### Planned
- ByteGrouping4LZ4 verification against a real captured chunk (currently only
  the codec itself is verified against zig-xet's reference vector; no real
  hf_xet capture using this scheme has been exercised end-to-end yet)
- V2 (`/v2/reconstructions`) multi-range fetch support - currently always
  signals a 501 fall-back to V1
- Global chunk-deduplication index (`GET /v1/chunks/{prefix}/{hash}`) -
  currently always 404
- Revision/branch support in the Hub API shim - every repo currently has a
  single implicit `main` revision

## [0.2.0] - 2026-09-04

### Added
- **Hub API shim** (`internal/hubserver`): a minimal implementation of
  huggingface.co's Hub REST API (distinct from the CAS API) - repo creation,
  preupload mode negotiation, `xet-{read,write}-token` issuance via response
  headers, ndjson commit parsing, and resolve/HEAD metadata with
  `X-Xet-Hash` - enough for the real `hf upload` / `hf download` CLI to
  target this server via `HF_ENDPOINT`. `cmd/xetd` gained a `-hub-addr` flag
  to run it alongside the CAS server.
- **Wire-compatible CAS HTTP API** (`internal/casserver`): the real Xet CAS
  protocol per xet-core's own `openapi/cas.openapi.yaml` - xorb upload/fetch,
  shard upload, file reconstruction with Range-based paging, chunk-dedup and
  telemetry stubs. Verified end-to-end against a live `hf_xet` Python
  client: byte-identical upload/download round-trips for both compressible
  and incompressible content.
- **BLAKE3-keyed Merkle hashing** (`internal/merklehash`): a byte-for-byte
  port of xet-core's `DataHash` type and Merkle-aggregation algorithm,
  verified against xet-core's own published reference vectors.
- **Xorb binary format** (`internal/xorbformat`) and **shard binary format**
  (`internal/shardformat`): ports of xet-core's on-wire chunk/xorb/shard
  layouts, each verified against real bytes captured from a live `hf_xet`
  upload.
- **From-scratch LZ4 decoder** (`internal/lz4`): an LZ4 block + frame
  decoder written directly from the public LZ4 format specifications (not
  ported from any existing implementation), needed to independently
  re-verify chunk hashes regardless of compression scheme.
- **ByteGrouping4 codec** (`internal/bg4`): the reverse transform for Xet's
  `ByteGrouping4LZ4` chunk compression scheme, cross-checked against
  [zig-xet](https://github.com/jedisct1/zig-xet)'s published test vector.
- **Pluggable storage backend** (`internal/storage`): a `Store` interface
  with filesystem (`fsstore`) and S3-compatible (`s3store`) implementations.
  The S3 backend uses a from-scratch AWS SigV4 request signer
  (`internal/sigv4`, verified against independently-computed HMAC chains and
  a live MinIO instance) instead of a third-party SDK.
- `integration-tests/hf_cli_roundtrip.sh`: drives the actual `hf` CLI
  (not this project's own client) through a full upload+download round-trip
  against the shared test server, wired into `integrationTests.sh` with a
  per-test timeout and SKIP semantics for environments without the optional
  `huggingface_hub`/`hf_xet` Python dependencies.
- `make pre-check` / `.DEFAULT_GOAL := help` / `make vet` targets.

### Changed
- Project renamed from `xet-lite` to `xet-server` (Go module path, folder
  name) to reflect the shift from a from-scratch dedup demo to a
  wire-compatible protocol server.
- `internal/api`'s original filesystem-backed chunk store was extracted into
  `internal/storage/fsstore` behind the new `storage.Store` interface.

### Fixed
- Real `hf_xet` clients upload xorbs and shards *without* a footer/lookup
  tables - the server now reconstructs chunk hashes, boundaries, and file
  indices itself by scanning headers, rather than requiring (and rejecting
  the absence of) a client-supplied footer.
- Shard file-info headers real clients set `MDB_FILE_FLAG_WITH_VERIFICATION`
  and `MDB_FILE_FLAG_WITH_METADATA_EXT` unconditionally; the shard reader now
  parses the corresponding verification/metadata_ext trailing entries
  instead of misreading everything after the first file header.
- `GET /v1/reconstructions/{file_id}` now honors the HTTP `Range` header and
  returns 416 once the requested range starts at or past EOF, matching how
  `hf_xet` pages through large-file downloads (previously always returned
  the same full-file term, desyncing the client's sequential writer on the
  second page).

## [0.1.0] - 2026-09-03

### Added
- Initial release as `xet-lite`: a simplified, non-wire-compatible
  re-implementation of the core idea behind Hugging Face's Xet storage -
  content-defined chunking (gear-hash rolling hash), content-addressed
  chunk store, JSON manifests for file reconstruction.
- `cmd/xetd` HTTP server (`POST /upload`, `GET /files/{id}`,
  `GET /files/{id}/manifest`, `GET /stats`) and `cmd/xet` CLI
  (`push`/`pull`/`stats`).
- Unit tests for all packages and a bash-based integration test harness
  (`integrationTests.sh` + `integration-tests/*.sh`) exercising a live
  server end-to-end.
- `LICENSE.md` (MIT), `.gitignore`, `Makefile` (`format`/`build`/`test`/
  `integration-test`/`clean`/`all`), and initial `README.md`.
