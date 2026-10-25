# Xet Server

A Go server that is **wire-compatible** with Hugging Face's real [Xet
storage protocol](https://huggingface.co/docs/hub/en/xet/index) - the
content-defined-chunking, dedup-first storage layer that replaces Git LFS
for large model files on the Hub. Point the real `hf` CLI
(`huggingface_hub` + `hf_xet`) at this server and it works: `hf upload`,
`hf download`, byte-identical round-trips, real BLAKE3 hashing, real
xorb/shard binary formats, real LZ4/byte-grouping compression.

This started as a simplified, non-wire-compatible chunking/dedup demo
(kept in `internal/chunk`, `internal/manifest`, `internal/api`, `cmd/xet`
for quick manual testing) and grew into a from-scratch, spec-driven
reimplementation of the actual protocol - verified end-to-end against a
live `hf_xet` client, with several real wire-format quirks discovered only
by capturing and replaying genuine client traffic. See
[docs/PROTOCOL.md](docs/PROTOCOL.md) for that story.

Also included: **`xet-proxyd`**, a caching pull-through proxy for the real
huggingface.co - not just a performance cache, but an offline-resilience
layer. Point it at the real Hub, use it like a normal `HF_ENDPOINT`, and
every repo/file it has successfully served once stays servable via `hf
download`/`hf upload` even after huggingface.co becomes unreachable -
including handing its cache directory to a plain `xetd` as a permanent,
disconnected replacement. See [Caching pull-through proxy](#caching-pull-through-proxy-xet-proxyd)
below.

---

# Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [Run the wire-compatible server](#run-the-wire-compatible-server)
  - [Authentication](#authentication)
  - [Point the real `hf` CLI at it](#point-the-real-hf-cli-at-it)
  - [Xet Data API + CLI](#xet-data-api--cli)
- [Caching pull-through proxy (`xet-proxyd`)](#caching-pull-through-proxy-xet-proxyd)
- [HTTP API](#http-api)
  - [Interactive API docs (Swagger UI)](#interactive-api-docs-swagger-ui)
- [Storage backends](#storage-backends)
- [Testing](#testing)
- [Documentation](#documentation)
- [Where this diverges from real Xet](#where-this-diverges-from-real-xet)
- [Troubleshooting](#troubleshooting)
- [License](#license)
- [Contributing](#contributing)
- [Acknowledgments & Related Projects](#acknowledgments--related-projects)

---

# Features

- **Wire-compatible CAS HTTP API** (`internal/casserver`): xorb
  upload/fetch, shard upload, file reconstruction with Range-based paging,
  matching xet-core's own `openapi/cas.openapi.yaml` - verified
  byte-identical against a real `hf_xet` client, for both compressible and
  incompressible content.
- **Hub API shim** (`internal/hubserver`): enough of huggingface.co's Hub
  REST API (repo create, preupload, `xet-{read,write}-token`, commit,
  resolve/HEAD) that the real `hf upload`/`hf download` shell commands work
  against this server via `HF_ENDPOINT` - including real, independent
  revisions/branches per repo, not just an implicit `main`.
- **`xet-proxyd`: a caching pull-through proxy for the real huggingface.co**
  (`cmd/xet-proxyd`, `internal/proxycas`, `internal/proxyhub`,
  `internal/hfclient`) - an offline-resilience layer, not just a
  performance cache: any repo metadata or xorb bytes it has successfully
  relayed once stay servable even after the real huggingface.co becomes
  unreachable, and its cache directory is a real `xetd` data directory a
  plain `xetd` can take over directly, no proxy process required. See
  [Caching pull-through proxy](#caching-pull-through-proxy-xet-proxyd).
- **Real BLAKE3-keyed Merkle hashing** (`internal/merklehash`): a
  byte-for-byte port of xet-core's `DataHash`, verified against xet-core's
  own published reference vectors - not an approximation.
- **Real xorb and shard binary formats** (`internal/xorbformat`,
  `internal/shardformat`), each verified against real bytes captured from
  a live `hf_xet` upload, including the footer-less upload behavior real
  clients actually use (see [docs/PROTOCOL.md](docs/PROTOCOL.md)).
- **From-scratch LZ4 decoder and ByteGrouping4 codec** (`internal/lz4`,
  `internal/bg4`): written directly from the public LZ4 spec / verified
  against a third-party reference implementation, so chunk hashes can be
  independently re-verified regardless of compression scheme.
- **Pluggable, streaming storage** (`internal/storage`): a `Store`
  interface with filesystem (`fsstore`) and S3-compatible (`s3store`)
  backends, built on `io.Reader`/`io.ReadCloser` rather than `[]byte` -
  neither backend ever buffers a full object in memory, so a multi-GB
  upload/download costs a fixed amount of memory. The S3 backend uses a
  from-scratch AWS SigV4 signer (`internal/sigv4`), no AWS SDK dependency.
  Verified end-to-end with real GGUF model files up to 27.6 GB.
- **Zero required external dependencies to build the demo path**; the
  protocol path adds exactly one pure-Go module
  (`github.com/zeebo/blake3`), pinned in `go.sum`.
- **Optional storage auto-pruning and request rate limiting**
  (`internal/eviction`, `internal/ratelimit`): bounded, observable
  defense-in-depth for a server left running against untrusted traffic -
  neither adds a dependency, and both are off unless explicitly enabled.
  `xetd` rate-limits uploads only (the expensive local operation there);
  `xet-proxyd` rate-limits every route on both ports, since even a read
  can trigger a real outbound call to the real huggingface.co.
- **Optional dedup-hit content verification** (`internal/storage`'s
  `VerifyingStore`): byte-compares an incoming upload against the stored
  blob on a dedup hit instead of trusting the content hash alone,
  bailing at the first mismatch - a hash-collision/corruption safety net,
  off by default since it roughly doubles I/O on a dedup hit.
- **A real global chunk-dedup index and V2 (multi-range) reconstruction**
  (`internal/casserver`): `GET /v1/chunks/{prefix}/{hash}` returns the
  actual shard bytes referencing a queried chunk (the real wire contract,
  confirmed against xet-core's own client source), and
  `GET /v2/reconstructions/{file_id}` returns the multi-range-optimized
  response shape instead of always falling back to V1.
- **Restart-surviving metadata persistence**: `casserver`/`hubserver`
  (and, identically, `xet-proxyd`'s embedded copies of each) periodically
  (and on graceful shutdown) checkpoint their in-memory
  reconstruction/repo indices to disk as an atomic JSON snapshot - see
  `-snapshot-interval` below.
- **Real-client regression fixtures**: several packages carry
  `testdata/` captured directly from a live `hf_xet` session, replayed in
  unit tests - the strongest guard against silently regressing wire
  compatibility.

# Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full system
diagram (upload/download sequence diagrams, package responsibility table,
and the key design decisions). Short version:

- `cmd/xetd` runs the CAS server, and - with `-hub-addr` - the Hub API shim
  as a second HTTP listener, matching how huggingface.co's real Hub and
  CAS are actually separate services.
- `cmd/xet-proxyd` runs a caching pull-through proxy in front of the real
  huggingface.co, on the same two-port shape as `xetd` - a drop-in
  alternative for the same ports, backed by the real Hub instead of being
  the only copy of the data. See
  [Caching pull-through proxy](#caching-pull-through-proxy-xet-proxyd).
- `cmd/xet` is a small CLI for the Xet Data API only (not the
  wire-compatible protocol - use the real `hf` CLI for that).

# Installation

## Git LFS

With `-hub-addr` set, xetd is also a Git LFS server: set a repo's `lfs.url`
to `http://<hub>/{owner}/{name}.git/info/lfs` and the stock `git-lfs`
client plus `git-xet` push LFS objects into the Xet CAS with chunk-level
dedup, pull them back over the basic transfer, and use `git lfs lock`.
With `-sync-folder` the data directory can be a Dropbox/Syncthing folder
shared by one xetd per machine, no server anywhere. See
[docs/GIT_LFS.md](docs/GIT_LFS.md).

## Prerequisites

- Go 1.27 or later
- GNU Make
- Bash (for integration tests)
- (Optional, for the real `hf` CLI round-trip test) `pipenv`, to install
  `huggingface_hub` + `hf_xet`
- (Optional) `merman-cli` or `mmdc` (mermaid-cli), to render Mermaid
  diagrams as SVG in `make docs`/`make docs-serve` - falls back to a
  source + mermaid.live link if neither is available

If `pipenv` can't reach `pypi.org` directly (a corporate proxy, an
air-gapped environment), copy `.env.example` to `.env` and set
`PIPENV_PYPI_MIRROR` to a reachable index mirror; `.env` is read by
`make install` and is gitignored.

## Build

```bash
make pre-check   # verify Go/bash are present
make build       # -> bin/xetd, bin/xet-proxyd, bin/xet
```

## Install

### Via `go install`

Requires Go 1.27 or later. Installs into `$(go env GOPATH)/bin`
(typically `~/go/bin`; add that directory to your `PATH` if it isn't
already):

```bash
go install github.com/guilt/xet-server/cmd/xetd@latest
go install github.com/guilt/xet-server/cmd/xet-proxyd@latest
go install github.com/guilt/xet-server/cmd/xet@latest
```

### Prebuilt binaries

Every tagged release publishes per-platform zips
(`xet-server-<version>-<platform>.zip`) from the [GitHub Releases
page](https://github.com/guilt/xet-server/releases) - each zip bundles all
three binaries (`xetd`, `xet-proxyd`, `xet`) plus this README, the
CHANGELOG, the LICENSE, CONTRIBUTING, the `docs/` directory (both the
Markdown sources and the browsable HTML generated by `make docs`,
Mermaid diagrams included), and a `VERSION` file. A `checksums.txt`
(SHA-256 of every zip) is published alongside them.

# Usage

## Run the wire-compatible server

```bash
# CAS server only, on :8420
./bin/xetd -addr :8420 -data ./xet-data

# CAS server + Hub API shim (needed for the real hf CLI), on :8420 / :8421
./bin/xetd -addr :8420 -hub-addr :8421 -data ./xet-data

# With storage auto-pruning (evict least-recently-used xorbs over 10GB,
# checked every 5 minutes) and per-source-IP upload rate limiting (5
# requests/sec sustained, burst of 20) - both optional, both off by default:
./bin/xetd -addr :8420 -data ./xet-data \
  -max-storage-bytes 10737418240 -eviction-interval 5m \
  -rate-limit-rps 5 -rate-limit-burst 20

# With dedup-hit content verification (see "Storage backends" below) and
# a faster persistence checkpoint interval than the 1-minute default:
./bin/xetd -addr :8420 -data ./xet-data -verify-dedup -snapshot-interval 15s
```

Opening either port's root path (`http://localhost:8420/` or, if
`-hub-addr` is set, `http://localhost:8421/`) in a browser shows a landing
page listing every endpoint that port serves - useful for orienting
yourself without needing to read this README first.

## Authentication

By default `xetd` enforces no authentication at all - any client can read
and write, matching this project's behavior prior to v0.8.0. Passing
`-auth-token <secret>` (or, preferably, setting `$XETD_AUTH_TOKEN`) requires
every request to carry `Authorization: Bearer <secret>`, split into
read/write scope per endpoint (uploads/commits need write; downloads/
reconstructions/resolve need read) the same way real Xet/HF Hub tokens
work. `-auth-token None` (the default) or leaving it unset disables
enforcement entirely.

Minted tokens (the short-lived credentials the Hub shim issues to `hf_xet`
and git-xet, and puts on git-lfs download links) are also **bound to one
repository**: the repo type and ID are inside the HMAC-signed payload, so a
token for `alice/one` gets `403` on `bob/two`'s read, write, and token-refresh
routes. A repo-scoped write token may create a new repo only inside its own
namespace; creating under another owner requires the shared secret. The
shared secret itself stays unrestricted (it carries the `admin` scope).

```bash
export XETD_AUTH_TOKEN="a-long-random-secret"
./bin/xetd -addr :8420 -hub-addr :8421 -data ./xet-data

./bin/xet push -server http://localhost:8420 -auth-token "a-long-random-secret" ./model.safetensors
# or, equivalently, export XET_AUTH_TOKEN (or HF_TOKEN, the same variable
# the real `hf` CLI reads) instead of passing -auth-token:
export XET_AUTH_TOKEN="a-long-random-secret"
./bin/xet push -server http://localhost:8420 ./model.safetensors
```

**Prefer the environment variable over the flag** ($XETD_AUTH_TOKEN /
$XET_AUTH_TOKEN) whenever the machine is shared or the command runs where
its argument list might be logged: a `-auth-token` flag value is visible to
any other local user via `ps -ef` / `/proc/<pid>/cmdline` and gets written
to shell history, while an environment variable set through a secrets
manager, a `.env` file kept out of history, or `read -s` is not. An
explicit `-auth-token` flag always takes precedence over the environment
variable if both are set, so scripts that need to override a
machine-wide/session-wide token can still do so per invocation.

`-auth-token`/the env vars above configure this project's built-in
`auth.StaticTokenAuth` (server) and `auth.BearerCredentialHelper` (client)
- a single shared secret. Both sides are defined as small interfaces
(`auth.Authenticator`/`auth.Principal` server-side,
`auth.CredentialHelper` client-side) in `internal/auth`, so implementing
your own (e.g. per-user tokens, JWT validation, mTLS) is a matter of
satisfying those interfaces and calling `SetAuthenticator`/setting
`client.Client.Cred` - no changes to `casserver`, `hubserver`, or
`internal/api` required.

## Point the real `hf` CLI at it

```bash
export HF_ENDPOINT="http://localhost:8421"   # the Hub shim's address
export HF_TOKEN="anything"                    # ignored unless xetd was started with -auth-token/$XETD_AUTH_TOKEN - see Authentication above

hf upload myuser/my-model ./model.safetensors model.safetensors
hf download myuser/my-model model.safetensors --local-dir ./downloaded
cmp ./model.safetensors ./downloaded/model.safetensors   # byte-identical
```

You can also drive `hf_xet`'s low-level `XetSession` Python API directly
against the CAS server's own address (`:8420` above) with no Hub API
involved at all - useful for isolating whether an issue is in the CAS
protocol or the Hub shim.

Want to run this as a real, standing mirror rather than a one-off local
test? See **[docs/MIRRORING.md](docs/MIRRORING.md)** for a full
step-by-step guide (securing it, pointing multiple machines at it,
troubleshooting).

## Xet Data API + CLI

A simple, non-wire-compatible gear-hash-CDC + JSON-manifest API is also
available for quick manual testing, mounted on the same `xetd` process at
`/v1/upload`, `/v1/files`, `/v1/stats` - sharing the `/v1` namespace with
the CAS protocol on a disjoint set of literal paths (`internal/api`'s
exported `UploadPath`/`FilesPrefix`/`StatsPath` constants are the single
source of truth for these, referenced by both `cmd/xetd`'s route table
and `internal/client`, so the path never drifts between server and
client). `-server` (both flags below are optional) falls back to
`$XET_SERVER`, then `http://localhost:8420`:

```bash
export XET_SERVER="http://localhost:8420"   # optional; -server overrides it per-invocation
./bin/xet push /path/to/model.safetensors
# -> file_id:  2d53223aa33715f0eff757537ed9cf8f
#    chunks:   28 total, 28 new
#    stored:   2000000 bytes (0.0% deduplicated)

./bin/xet push /path/to/model-v2.safetensors   # a near-duplicate checkpoint
# -> chunks:   30 total, 4 new
#    stored:   436017 bytes (81.0% deduplicated)

./bin/xet pull -out ./restored.safetensors 2d53223aa33715f0eff757537ed9cf8f
./bin/xet stats
```

**No per-file ownership/isolation.** `file_id` is the SHA-256 of the
uploaded content - this API has no repo or user concept at all, so `-auth-token`
here (if enabled) only gates read/write access to the API as a whole, not
per-file: any caller with a valid read-scoped token (or none, if auth is
disabled) can fetch any `file_id` it knows, the same trust model as CAS's
own `/v1/xorbs/{hash}`. File IDs are not secrets and this store is not
multi-tenant - don't run it multi-tenant without adding that isolation
yourself first.

# Caching pull-through proxy (`xet-proxyd`)

`xet-proxyd` sits in front of the **real** huggingface.co and transparently
caches everything it relays - not primarily for speed, but for
**offline resilience**: once it has successfully served a repo's metadata
or a file's xorb bytes, that data keeps being servable via `hf download`/
`hf upload` even if huggingface.co goes down, gets rate-limited, or
disappears entirely. It's built by embedding the exact same
`internal/casserver.Server`/`internal/hubserver.Server` engines `xetd`
uses, rather than reimplementing caching logic separately - so its cache
directory is a real `xetd` data directory a plain `xetd` can take over
directly, with no proxy process running at all (see
[Offline handoff](#offline-handoff-proving-the-point) below).

```bash
# Two ports, same shape as xetd: -addr (CAS-facing), -hub-addr (Hub-facing).
# Point HF_ENDPOINT at -hub-addr and the real hf CLI works through it
# end-to-end, same as pointing it at a local xetd.
./bin/xet-proxyd -addr :8420 -hub-addr :8421 -data ./xet-proxy-data

export HF_ENDPOINT="http://localhost:8421"
export HF_TOKEN="anything"   # forwarded upstream unchanged - see below
hf download someuser/some-model --local-dir ./downloaded
```

Or via `make run-proxy` (same as above, with `./xet-proxy-data`).

**Verified end-to-end against the real huggingface.co** (not just this
project's own local stand-ins): a real `hf download` of a Xet file through
the proxy returns a byte-identical copy (the proxy caches the file's xorb
bytes via the presigned CDN URLs the real CAS's reconstruction returns),
and a real `hf upload` of a small (Git LFS mode) and a large (Xet mode)
file both succeed through the proxy to the live Hub. Use the `:port` form
for `-addr`/`-hub-addr` (`:8420`, not `127.0.0.1:8420`): the default CAS
URL this proxy hands out to clients is built as `http://localhost<addr>`,
which is correct for `:8420` but would mangle an explicit host. For a
custom externally-reachable address, pass `-cas-url http://<host>:<port>`
explicitly.

Same as `xetd`, opening either port's root path in a browser shows a
landing page ("Xet Proxy Server" / "Xet Proxy Server - Hub API shim")
listing that port's endpoints; the CAS-facing port also serves the same
offline Swagger UI at `/api-docs/` (identical spec - the wire protocol is
the same one `xetd` implements). Note the CAS-facing port can't answer
anything about a repo it hasn't seen yet until the Hub-facing port relays
at least one real Hub call - see the "bootstrap" note below.

**Every request that can't be served from cache is relayed live to the
real huggingface.co** (`-upstream-hub-url`, defaulting to
`https://huggingface.co`, falling back to `$HF_URL`) - the caller's own
`Authorization` header is forwarded upstream completely unchanged
(`internal/hfclient`'s pure-passthrough design: this proxy never holds or
uses a credential of its own). `-auth-token`/`$XET_PROXYD_AUTH_TOKEN`
gates access to **this proxy itself** - a separate concern from the
upstream credential entirely.

**Expired Xet access tokens are healed transparently.** Xet's per-repo
access tokens are short-lived, and on a long, high-concurrency download
(e.g. `hf download` of a 900+-file dataset) a token can expire between
the client's refresh and the moment a file's reconstruction is requested
from the real CAS - which answers `401 Unauthorized` for a repo the client
was just downloading from successfully. `xet-proxyd` detects that 401 on
the CAS-facing port, mints a fresh replacement token from the real Hub
using the **same credential the client already presented** (never a secret
this proxy holds itself), and retries the request once - so the failure is
invisible to the client instead of aborting the download. The replacement
is scoped to the same repo/ref/read-vs-write kind as the original, so this
can only ever restore access the client already had. Relatedly, the
stale-fallback for cached xet tokens refuses to serve a token whose `exp`
has already passed: a transient upstream `xet-{read,write}-token` failure
can never hand the client a token that is dead on arrival, it surfaces the
upstream error instead (a clean, retryable failure).

**Authorization-dependent caches are per-caller.** The upstream xet-token
cache is keyed by a fingerprint of the caller's `Authorization` header
(alongside repo/ref/kind), and repo-info/tree/resolve freshness is
credential-scoped too. One caller's token or private-repo metadata can
never be served to another caller, and an upstream `401`/`403` is returned
instead of being masked by a stale cached value. The token cache and
401-heal index are process-memory only - they are never written into the
`-data` snapshots.

**Any upstream failure - network error, timeout, 5xx - falls back to
whatever is already cached, no matter how old**, rather than erroring;
this fallback is the whole reason the proxy exists. `-cache-ttl` (default
`-1`, meaning "always try upstream first") controls how long cached Hub
metadata (repo-info, tree, resolve) and same-credential xet tokens are served without even
attempting a live refresh; it never affects the CAS byte cache, which is
content-addressed and can't go stale by definition. `-metadata-call-timeout`
(default `30s`) bounds each individual metadata call so a slow-but-not-dead
upstream doesn't hold up the fallback path longer than necessary - it
never applies to tree listing, which pages internally within one call and
can legitimately take longer for a very large repo.

`-no-cache` disables all of this - a pure-relay escape hatch (every
request goes straight to upstream, nothing is read or written locally)
for when you specifically want a stateless relay rather than the default
offline-resilient caching mode.

**Bootstrap note: the CAS-facing port needs the Hub-facing port to have
relayed at least one real request first.** Real Xet CAS has no single
well-known base URL - each repo's Hub `xet-{read,write}-token` response
hands back a *per-repo* CAS URL, and the CAS-facing proxy only learns it
as a side effect of the Hub-facing proxy relaying one of those calls. A
request straight to `-addr` (a raw `curl`, or `hf_xet`'s low-level API
pointed directly at the CAS port) before ANY traffic has gone through
`-hub-addr` gets `503 upstream CAS URL not yet known`. Always drive
traffic through `HF_ENDPOINT` pointed at `-hub-addr` first - a real `hf
download`/`hf upload` (or even just one xet-token round-trip) - and the
CAS port works for the rest of that process's life, including everything
already cached from a previous run.

Rate limiting (`-rate-limit-rps`/`-rate-limit-burst`, off by default)
gates **every route on both ports**, not just uploads like `xetd`'s own
`-rate-limit-rps` - a cache-missing read costs a real outbound call to
huggingface.co just as much as a write does, so both need the same
protection. One shared limiter covers both ports, so a client can't double
its effective budget by splitting requests across them.

`-snapshot-interval` (default `1m`) persists the CAS xorb/file index and
the Hub repo/revision/file/resolve metadata to `-data` - using the
**exact same filenames** `xetd` itself reads and writes
(`casserver-snapshot.json`/`hubserver-snapshot.json`), which is what makes
the handoff below work at all. Upstream credentials and xet access tokens
are deliberately **not** persisted. For a read-only offline handoff with a
large index, start the handed-off `xetd` with `-snapshot-interval 0` so it
does not rewrite a multi-GB snapshot every minute.

## Offline handoff, proving the point

```bash
# 1. Cache something while online:
./bin/xet-proxyd -addr :8420 -hub-addr :8421 -data ./xet-proxy-data &
HF_ENDPOINT=http://localhost:8421 hf download someuser/some-model --local-dir ./downloaded

# 2. Stop the proxy (a final snapshot is taken automatically):
kill %1

# 3. huggingface.co is gone / unreachable / you're fully offline now.
#    Point a PLAIN xetd at the SAME data directory - no -upstream-hub-url,
#    no network, nothing but what step 1 already cached:
./bin/xetd -addr :8420 -hub-addr :8421 -data ./xet-proxy-data -snapshot-interval 0

# 4. The exact same download still works, byte-identical, forever:
HF_ENDPOINT=http://localhost:8421 hf download someuser/some-model --local-dir ./downloaded-again
cmp -r ./downloaded ./downloaded-again
```

This isn't a hypothetical - `integration-tests/xet_proxyd_offline_handoff.sh`
runs exactly this sequence (against a local stand-in Hub, so it needs no
network access) as part of `make integration-test`: upload+download
through the proxy via the real `hf` CLI, shut the proxy down, tear down
its upstream entirely, start a fresh plain `xetd` on the handed-off data
directory, and download again with nothing else running. This is `xet-proxyd`'s
whole reason to exist: a practical path off huggingface.co, not just a
faster mirror of it.

> **Partial xorb slices are cached too.** A file's reconstruction
> `fetch_info` gives the byte ranges *that file* needs, which for a
> deduplicated repo is frequently only part of a xorb originally written
> for some other file (e.g. chunks 15-21 of 1042). Those bytes cannot
> reproduce the original xorb's hash, so the proxy does not store them
> under that hash. Instead it fetches the cited chunk group, repackages
> those chunks as a new xorb under **its own** content hash, and rewrites
> the file's terms to reference it. The cached file is complete,
> hash-verifiable, and works offline after the handoff above - including
> heavily deduplicated datasets.
>
> A file still falls back to a live relay if `fetch_info` leaves a gap in
> a term's coverage (an incomplete/malformed upstream response): the
> download succeeds from the CDN, but that file is not cached. The proxy
> logs that at `DEBUG` (`proxycas: file not cacheable...`). Non-Xet blobs
> relayed live are likewise not cached; for a library that includes those,
> see the download-then-upload approach in
> [MIRRORING.md section 10](docs/MIRRORING.md).
>
> This was verified against the real Hub with a `bigcode/the-stack-v2`
> file whose reconstruction cites only a 222-chunk slice of a shared
> xorb: online download through the proxy, then a plain `xetd` on the
> same `-data` directory with no upstream, produced a byte-identical
> SHA-256.

# HTTP API

## Interactive API docs (Swagger UI)

Every endpoint below is also documented as an OpenAPI 3.0 spec
(`docs/openapi.yaml` - hand-authored and verified against the actual
handler source, not generated) and served through a fully offline Swagger
UI at `/api-docs/` on the CAS server's address:

```bash
./bin/xetd -addr :8420 -data ./xet-data
open http://localhost:8420/api-docs/   # or just visit it in a browser
```

"Fully offline" means exactly that: the Swagger UI static assets
(`third_party/swagger-ui-dist`, vendored from the
[swagger-ui](https://github.com/swagger-api/swagger-ui) project) and the
spec itself are both compiled directly into the `xetd` binary via Go's
`embed` package (see `internal/apidocs`) - no CDN dependency, and it works
identically on an air-gapped machine.

## CAS protocol (wire-compatible, mounted at `/v1`, `/v2`)

- `POST /v1/xorbs/{prefix}/{hash}` - upload a serialized xorb (chunk
  headers + payloads, no footer - see PROTOCOL.md)
- `GET /v1/xorbs/{prefix}/{hash}` - fetch raw (possibly compressed) xorb
  bytes, honors `Range`
- `POST /v1/shards` - upload a serialized shard (file/xorb info sections,
  no footer)
- `GET /v1/reconstructions/{file_id}` - file -> xorb/chunk-range map,
  honors `Range`, returns `416` at EOF
- `GET /v1/chunks/{prefix}/{hash}` - global chunk-dedup lookup: returns
  the raw bytes of whichever uploaded shard referenced this chunk hash
  (the real wire contract - a client parses the shard itself), `404` if
  no uploaded shard has ever referenced it
- `GET /v2/reconstructions/{file_id}` - multi-range-optimized
  reconstruction: same underlying terms/byte-ranges as V1, grouped by
  xorb (one signed URL covering multiple ranges) instead of one entry per
  term
- `POST /v1/telemetry` - no-op ack
- `GET /v1/storage-stats` - eviction policy stats (operator-facing; not
  part of the real Xet CAS API - see [Storage backends](#storage-backends))

## Hub API shim (mounted on a separate port via `-hub-addr`)

- `POST /api/repos/create`
- `GET /api/{repo_type}s/{repo_id}/revision/{revision}` - repo info at a
  revision (huggingface_hub's `snapshot_download` resolves this before a
  whole-repo `hf download`)
- `GET /api/{repo_type}s/{repo_id}/tree/{revision}` - list every file
  committed to a revision
- `POST /api/{repo_type}s/{repo_id}/branch/{branch}` - create a branch
- `POST /api/{repo_type}s/{repo_id}/preupload/{revision}`
- `GET /api/{repo_type}s/{repo_id}/xet-{read,write}-token/{revision}`
- `POST /api/{repo_type}s/{repo_id}/commit/{revision}`
- `HEAD`/`GET /{repo_id}/resolve/{revision}/{filename}`

## Xet Data API (mounted at `/v1`, alongside the CAS protocol)

- `POST /v1/upload?name=<optional>` - chunks + dedups the uploaded file
- `GET /v1/files/{id}` / `GET /v1/files/{id}/manifest` / `GET /v1/stats`

# Storage backends

`internal/storage.Store` is the abstraction both `casserver` and the Xet
Data API store chunk/xorb bytes through:

- **`fsstore`** - content-addressed filesystem directory (the default)
- **`s3store`** - any S3-compatible endpoint (AWS S3, MinIO), signed with
  the from-scratch `internal/sigv4` signer. Set `XET_S3STORE_LIVE_TEST=1`
  plus `XET_TEST_S3_*` env vars to run its tests against a real MinIO
  instance.

## Storage auto-pruning, upload rate limiting, dedup verification, and persistence

All off/on-defaults below; opt in or tune via `xetd` flags:

- `-max-storage-bytes N -eviction-interval 5m` - once total xorb storage
  exceeds `N` bytes, a background sweep (`internal/eviction`) deletes
  least-recently-accessed xorbs (upload or fetch both count as access)
  until back under budget, skipping any xorb with a fetch currently in
  progress. `GET /v1/storage-stats` reports the configured budget and
  cumulative evictions/bytes freed. A client that later needs an evicted
  xorb must re-upload it - real Xet clients already treat CAS storage as
  non-permanent and handle this by re-deriving from the source file. Off
  by default.
- `-rate-limit-rps N -rate-limit-burst N` - caps xorb/shard uploads per
  source IP via a hand-rolled token bucket (`internal/ratelimit`, no new
  dependency). Exceeding the limit returns `429` with `Retry-After`.
  Fetch/reconstruction/HEAD traffic is never rate-limited. Off by default.
- `-verify-dedup` - on every dedup hit (a `Put` for a content hash that
  already exists), byte-compare the incoming upload against the stored
  blob instead of trusting the content hash alone, bailing at the first
  mismatched byte rather than reading either side in full
  (`internal/storage.VerifyingStore`). A mismatch (a hash collision or
  undetected storage corruption) refuses the write - the original stored
  blob is never overwritten - and logs at `Error`, distinct from routine
  request-failure logging. Roughly 10x slower than the default trust-the-hash
  path on a dedup hit (a full extra read), which is why it's opt-in, not
  the default. Off by default.
- `-snapshot-interval 1m` - how often `casserver`/`hubserver`'s in-memory
  reconstruction/repo indices are checkpointed to `-data` as JSON (an
  atomic stage-then-rename write, the same pattern the storage backends
  use), so they survive a restart. A graceful shutdown (`Ctrl-C`/`SIGTERM`)
  always takes one final snapshot first. This is a periodic checkpoint,
  not a write-ahead log - anything written between two checkpoints is
  lost on an *un*graceful termination (a crash, `kill -9`, power loss);
  see [docs/PROTOCOL.md](docs/PROTOCOL.md)'s persistence section for the
  full tradeoff writeup. Set to `0` to disable periodic snapshotting
  (a final snapshot is still taken on graceful shutdown). Defaults to 1
  minute.

## Reclaiming space: the standalone server versus the proxy

The two binaries play different roles, and each has its own tool for a
store that must not grow without bound:

- **`xet-proxyd` is a cache** in front of huggingface.co. Every xorb it
  holds can be fetched again, so deleting the least-recently-used ones
  is always safe; that is what `-max-storage-bytes` eviction is for.
- **`xetd` is the only copy** of what was pushed to it. Eviction there
  deletes xorbs that files still reference (leave `-max-storage-bytes`
  off), and the server cannot tell on its own which files are still
  wanted: a file pushed through git-lfs is live as long as some git ref
  reaches its pointer, and only git knows that. So the operator says
  what to keep and `xetd gc` deletes the rest:

  ```bash
  # on the git host, for every repo the server backs
  git -C /srv/git/team/game.git lfs ls-files --all --long > /tmp/keep.txt
  # against the running server, with the shared secret
  xetd gc -server http://xet:8420 -auth-token "$XETD_AUTH_TOKEN" -keep /tmp/keep.txt -dry-run
  xetd gc -server http://xet:8420 -auth-token "$XETD_AUTH_TOKEN" -keep /tmp/keep.txt
  ```

  Files committed through the Hub shim (`hf upload`) are kept without
  being listed; the shim's registry is the record that they are wanted.
  Everything else is dropped from the index, the affected shards are
  rewritten, unreferenced xorbs are deleted from the store, and a
  snapshot is taken. The report says what happened (`-json` for the raw
  form). Only the shared secret may run it (`POST /v1/gc` needs the
  `admin` scope, which no minted token carries); with no auth
  configured anyone can, like everything else.

  **The grace period is the part to understand before lowering it.** A
  xet client keeps the shards of its own uploads for three weeks and
  deduplicates against them without asking the server, and it caches
  every dedup answer the server gave it for the same three weeks. A
  shard it uploads later may therefore reference a xorb the server has
  not heard about since; delete that xorb and the new file cannot be
  downloaded, and nothing says so at push time. `xetd gc` therefore
  never deletes a xorb uploaded, fetched or advertised in a dedup
  answer within the grace (`-gc-grace` on the server, `-grace` per run;
  default 22 days), and it keeps every file whose shard arrived within
  the grace even if the keep list does not name it yet (a push whose
  git ref has not moved). Growth is bounded by live content plus three
  weeks of churn. `-grace 0` is for a store whose clients you control
  (the integration tests, a single machine whose cache you cleared).

  Not available with `-sync-folder`: other replicas may still be
  advertising or indexing what one replica deletes.

# Testing

```bash
make test               # unit tests, all packages
make test-race          # unit tests under the race detector
make fuzz-seeds         # replay every committed fuzz corpus (fast, deterministic)
make test-fuzz          # fuzz every target, 30s each (override: FUZZTIME=5m)
make integration-test   # bash integration suite against a live server
```

`make test-fuzz` depends on `fuzz-seeds`, so every previously-found crash
(committed under `testdata/fuzz/`) is replayed before any time is spent
hunting for new inputs - a regression shows up immediately rather than
after `FUZZTIME` per target. `-race` and `-fuzz` are separate targets on
purpose: the race detector costs roughly an order of magnitude in
execution speed, so combining them within a fixed time budget explores far
fewer inputs. The race detector also requires a 64-bit toolchain (a 32-bit
Go/MinGW setup fails at startup with `exit status 0xc0000139`), which is
why CI runs it on 64-bit Linux.

`integrationTests.sh` starts one `xetd` instance (CAS + Hub shim) and runs
every script in `integration-tests/`, with a per-test timeout so a hang
doesn't block the suite. `integration-tests/hf_cli_roundtrip.sh` drives the
**real, unmodified `hf` CLI** through a full upload+download round-trip -
the strongest compatibility check available - and skips cleanly (not a
failure) if `pipenv`/its environment aren't set up. `integration-tests/xet_proxyd_offline_handoff.sh`
proves `xet-proxyd`'s whole reason to exist the same way: real `hf`
upload+download through a running proxy, then the proxy AND its upstream
are both torn down entirely and a plain `xetd` takes over the proxy's data
directory directly - the same download must still succeed, byte-identical,
with nothing but that directory:

```bash
make install             # pipenv --python 3.14 && pipenv install
make integration-test    # now includes hf_cli_roundtrip.sh, xet_proxyd_offline_handoff.sh, multi_client_*.sh
```

`integration-tests/multi_client_*.sh` run that same real `hf` CLI as
several **machines** - each with its own `HF_HOME`, `HF_XET_CACHE` and
token - against one `xetd`. A xet client dedups against its own shard
cache before it asks the server, so a single cache never parses the
server's global-dedup answer; only these tests do. They assert the
cross-client path from the server's DEBUG log and the client's log (a
dedup query answered 200 and parsed as `found`, reconstructions served to
a machine that never uploaded), so they cannot pass by uploading
everything twice.

See [CONTRIBUTING.md](CONTRIBUTING.md#2-running-tests) for the full test
layer breakdown, including why several packages carry real-client
`testdata/` fixtures, native Go fuzz tests for every wire-format parser,
adversarial/chaos tests against a live server, and dedup/hashing/
compression benchmarks.

# Documentation

- **[docs/FAQ.md](docs/FAQ.md)** - why Xet's chunking/dedup model exists
  at all instead of plain S3/HTTP hosting, why this project exists, why
  `xet-proxyd` exists, and other questions worth answering once instead
  of repeatedly
- **[docs/MIRRORING.md](docs/MIRRORING.md)** - practical guide to
  self-hosting your own model mirror: `hf download`/`hf upload` against
  your own server instead of huggingface.co, step by step, including
  `xet-proxyd`'s transparent-caching alternative
- **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** - system diagram,
  upload/download sequence diagrams, package responsibility table, design
  decisions
- **[docs/PROTOCOL.md](docs/PROTOCOL.md)** - wire-compatibility deep dive:
  every place the real client's behavior diverges from the documented spec,
  how each was discovered, and why the fix is correct
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - dev setup, test layers, doc-comment
  conventions, branching/PR conventions
- **[CHANGELOG.md](CHANGELOG.md)** - release history

Package-level godoc comments are the source of truth for implementation
details not covered above:

```bash
go doc ./internal/merklehash
go doc ./internal/casserver
```

`make docs` regenerates the committed `docs/godoc/*.md` package reference
(via `go doc -all`) and renders every Markdown doc in this repo to
browsable HTML in `docs/build/`; `make docs-serve` does the same and then
serves it locally. Both are implemented by `scripts/build_docs.go` (its
own Go module, so the main `xet-server` module keeps zero external
dependencies).

# Where this diverges from real Xet

Every divergence tracked in prior versions of this doc has been closed:
real revisions/branches, V2 reconstruction, a global chunk-dedup index,
restart-surviving persistence (all as of v0.7.0), pluggable
authentication/authorization (as of v0.8.0 - see
[Authentication](#authentication)), and - as of v1.0.0 - `xet-proxyd`
working against the **real** huggingface.co end to end (the v0.9.0 proxy
was verified only against this project's own local stand-ins; the
real-Hub gaps found - resolve redirects, presigned-URL xorb caching,
Content-Type headers, raw write-body relay, Git LFS passthrough - are all
fixed and documented in [CHANGELOG.md](CHANGELOG.md)).

`xet-proxyd` has one known, deliberate gap: on a cold
start with `-hub-addr` disabled (or before the Hub-facing port has relayed
any traffic), the CAS-facing port has no way to learn the real upstream
CAS base URL and returns `503` for anything it doesn't already have
cached - see the bootstrap note in
[Caching pull-through proxy](#caching-pull-through-proxy-xet-proxyd).
This is inherent to how real Xet CAS's base URL is discovered (per-repo,
via the Hub's own token response, not a fixed well-known address), not a
gap this project could close without deviating from the real protocol.

# Troubleshooting

### Debugging `xetd` itself
Run `xetd` with `DEBUG=1` to log every HTTP request it receives (method,
path, status, duration) plus commit/shard/resolve lookup details at debug
level via the standard library's `log/slog`:

```bash
DEBUG=1 ./bin/xetd -addr :8420 -hub-addr :8421 -data ./xet-data
```

This is the fastest way to see whether a request from `hf upload`/`hf
download` (or anything else) actually reached the server, and what it did
once it got there - see [docs/PROTOCOL.md](docs/PROTOCOL.md)'s "How these
were found" section for how this was used to track down real bugs.
`DEBUG=1 ./bin/xet-proxyd ...` does the same for the proxy - useful for
telling whether a slow/failed request actually reached the real
huggingface.co or was served from cache. `xet` (the CLI client) has no
`DEBUG` flag: it's a one-shot command that already prints its result
directly, not a long-running server with request traffic to log.

### `hf upload`/`hf download` hangs or times out
If you're in a sandboxed/corporate network that proxies all outbound
traffic (including `localhost`), `hf_xet`'s Rust HTTP client may not
consistently honor `NO_PROXY`/`no_proxy` for localhost, and the upload call
hangs. This is an environment limitation, not a xetd bug - the identical
upload/download flow works when driven directly against the CAS server via
`hf_xet`'s low-level Python API. Try setting
`NO_PROXY=localhost,127.0.0.1` / `no_proxy=localhost,127.0.0.1`, or run
outside the proxied environment. `integration-tests/hf_cli_roundtrip.sh`
enforces a timeout so this fails visibly instead of hanging the test suite.

### Integration tests fail to start the server
The runner picks ports `18420`/`18421` by default to avoid colliding with a
`make run`-style instance on `8420`/`8421`. Override with
`XETD_PORT=<port> XETD_HUB_PORT=<port> make integration-test` if those are
also taken.

### `make integration-test` reports "Operation not permitted" creating temp files
The runner uses `$TMPDIR` (or `/tmp` if unset) for all scratch state. Make
sure your environment allows writes there.

### Chunk counts differ between two very similar files more than expected (Xet Data API only)
The Xet Data API's chunker targets an average chunk size of 64 KiB; edits
smaller than that still land inside one chunk boundary, and byte-level
insertions can shift downstream boundaries until the rolling hash
resynchronizes. Expected content-defined-chunking behavior, not a bug.

# License

MIT License - see [LICENSE.md](LICENSE.md) for details.

# Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. Short version:

1. Fork the repository, branch from `main`
2. `make all` before opening a PR (format, vet, build, unit tests,
   integration tests)
3. PR titles follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
4. If you touch protocol/wire-format behavior, read
   [docs/PROTOCOL.md](docs/PROTOCOL.md) first

# Acknowledgments & Related Projects

This project only exists because of work other people published openly.
Thank you to:

- [Hugging Face](https://huggingface.co) and the **Xet** team for
  designing and documenting [the Xet protocol](https://huggingface.co/docs/hub/en/xet/index)
  this project reimplements, and for
  [xet-core](https://github.com/huggingface/xet-core) (the real Rust
  implementation this project is wire-compatible with) - the ultimate
  source of truth every byte here was checked against.
- [Taylor Brown (@Tay-Tay)](https://github.com/Tay-Tay) for the keep-set garbage-collection
  patches (`xetd gc`, GC grace and keep semantics) integrated in v1.2.0.
- [Jannes Stubbemann (@stubbi)](https://github.com/stubbi) and the
  [openxet](https://github.com/stubbi/openxet) project for an independent
  Xet protocol implementation and a thorough security review, which found
  the token-cache isolation and unkeyed global-dedup issues fixed in
  v1.3.0.
- [jedisct1](https://github.com/jedisct1) for
  [zig-xet](https://github.com/jedisct1/zig-xet), an independent
  third-party reference implementation used to verify this project's own
  `ByteGrouping4` codec against a second, unrelated source rather than
  trusting a single implementation.
- [zeebo](https://github.com/zeebo) for
  [`blake3`](https://github.com/zeebo/blake3), the one external Go
  dependency this project takes on for its main module - a correct,
  well-tested BLAKE3 implementation is exactly the kind of primitive
  worth depending on rather than reimplementing (see
  [docs/FAQ.md](docs/FAQ.md) for why).
- The [swagger-ui](https://github.com/swagger-api/swagger-ui) project,
  whose static assets (vendored under `third_party/swagger-ui-dist`,
  Apache-2.0 - see its own `VENDORED.md`) power this project's fully
  offline `/api-docs/` UI.
- [yuin/goldmark](https://github.com/yuin/goldmark),
  [alecthomas/chroma](https://github.com/alecthomas/chroma), and
  [abhg/goldmark-mermaid](https://github.com/abhg/goldmark-mermaid),
  which render this repo's own Markdown docs (`scripts/build_docs.go`,
  its own module so these never touch the main `xet-server` module's
  dependency graph).
- The [Git LFS](https://git-lfs.com/) project, for defining the large-file
  Git workflow that Xet's chunking/dedup model improves on - and for
  being the widely-understood baseline this README's
  [FAQ](docs/FAQ.md#why-not-just-put-model-files-in-s3-or-any-plain-http-file-host-instead-of-building-all-this)
  compares against.
- Everyone who publishes public specs (LZ4, AWS Signature Version 4,
  OpenAPI 3.0) clearly enough that a from-scratch, independently-verified
  implementation is actually possible without access to any reference
  server's source code.
