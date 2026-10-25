# Mirroring / self-hosting your own models with Xet Server

A practical, copy-pasteable guide to running your own Hugging Face
Hub-compatible model host, so `hf download` and `hf upload` work against
your own server instead of huggingface.co - for private model mirrors, air-gapped
environments, or just keeping a large set of checkpoints somewhere you
control. Sections 1-8 cover `xetd`, where you deliberately upload the
content you want hosted; section 9 covers `xet-proxyd`, which instead
transparently caches whatever's requested through it from the real
huggingface.co - read that section if you want a mirror with no manual
upload step, or one that stays useful even after huggingface.co itself
becomes unreachable.

This guide only uses the real `hf` CLI (from `huggingface_hub`) - nothing
in `cmd/xet`/`internal/api` (the "Xet Data API") is needed for this. If
you've never used this project before, skim
[Architecture](../docs/ARCHITECTURE.md) first; this guide assumes you
already have `xetd`/`xet-proxyd` built (`make build` from the repo root).

## 1. What you're actually running

Real Hugging Face splits "the Hub" (repo/commit/metadata API) and "Xet CAS"
(the actual chunked, deduplicated blob storage) into two separate
services. `xetd` mirrors that split as two listeners from one binary:

- **CAS port** (`-addr`, default `:8420`) - the actual chunk/xorb storage.
- **Hub shim port** (`-hub-addr`, e.g. `:8421`) - the repo API `hf` talks to
  directly; it hands back a token + the CAS address so `hf`'s `hf_xet`
  layer can talk to CAS itself for the actual bytes.

Both need to be running for `hf upload`/`hf download` to work - the Hub
shim on its own can't move any bytes; the CAS server on its own doesn't
know what a repo is.

## 2. Start the server

```bash
./bin/xetd -addr :8420 -hub-addr :8421 -data ./xet-data
```

`./xet-data` is a plain directory - everything (chunks, xorbs, shard
metadata, and the Hub shim's repo/commit index) lives under it, and
survives a restart via periodic snapshotting (see
[Storage backends](../README.md#storage-backends) in the main README). A
large handoff index can be several GB; for read-only offline serving pass
`-snapshot-interval 0`, otherwise the server rewrites that whole snapshot
every minute.

For a real, long-running mirror, point `-data` at a disk with enough room for
every model you plan to host, plus growth - see
[storage auto-pruning](../README.md#storage-auto-pruning-upload-rate-limiting-dedup-verification-and-persistence)
if you want to cap it instead.

Opening `http://<host>:8420/` or `http://<host>:8421/` in a browser shows a
landing page confirming the server is up and listing what each port
serves - useful for a first sanity check before touching the `hf` CLI at
all.

## 3. Secure it before anyone else can reach it

If this server will be reachable by anyone other than you (even just other
users on the same machine), turn on authentication before going further -
skipping this step means **anyone who can reach the port can upload or
download anything**:

```bash
export XETD_AUTH_TOKEN="$(openssl rand -hex 32)"   # generate once, keep it secret
./bin/xetd -addr :8420 -hub-addr :8421 -data ./xet-data
```

Write that token down now - you'll pass the exact same value as `HF_TOKEN`
in the next step. See [Authentication](../README.md#authentication) in the
main README for the full flag/env-var precedence and what read vs. write
scope means here. If this server is genuinely only ever reachable by you
(e.g. `-addr 127.0.0.1:8420` on your own laptop), you can skip this and
`HF_TOKEN` can be any placeholder string - the server just won't check it.

## 4. Point `hf` at it

```bash
export HF_ENDPOINT="http://<host>:8421"     # the Hub shim port, not the CAS port
export HF_TOKEN="<the token from step 3, or any string if auth is off>"
```

`HF_ENDPOINT` is `huggingface_hub`'s own variable - every `hf` command
(and every `huggingface_hub`/`hf_xet` Python call) respects it
automatically, so nothing else needs to change to point an existing
workflow at your server instead of huggingface.co.

## 5. Upload (host) a model

```bash
hf upload myuser/my-model ./local-model-dir --repo-type model
```

- `myuser/my-model` is created automatically on first upload - there's no
  separate "create repo" step to run by hand.
- Every file gets chunked and deduplicated against everything already
  stored on this server (not just within one repo) - re-uploading a
  near-identical checkpoint after a small fine-tune only transfers and
  stores what actually changed.
- Pushing to a named revision that doesn't exist yet creates it, exactly
  like a real Hub repo's branch:

  ```bash
  hf upload myuser/my-model ./local-model-dir --revision experiment-1
  ```

  `main` always exists once the repo does (created implicitly, matching a
  real repo always having a default branch); any other revision name is
  created the first time something is committed to it. Revisions are
  fully independent - the same file path can hold different content on
  `main` vs. `experiment-1`.

## 6. Download (mirror) a model

```bash
hf download myuser/my-model --local-dir ./downloaded
```

```bash
# a specific revision:
hf download myuser/my-model --revision experiment-1 --local-dir ./downloaded

# a single file, rather than the whole repo:
hf download myuser/my-model config.json --local-dir ./downloaded
```

This is the actual mirroring operation: point `HF_ENDPOINT` at your
server, run `hf download`, and every file streams from your own CAS
storage - no request to huggingface.co is made at all once `HF_ENDPOINT`
is set.

## 7. Verify it end-to-end

```bash
hf upload myuser/verify-mirror ./some-file.bin
hf download myuser/verify-mirror some-file.bin --local-dir ./verify-out
cmp ./some-file.bin ./verify-out/some-file.bin && echo "byte-identical"
```

If that round-trip is byte-identical, your mirror is working correctly.
This exact round-trip is also what `integration-tests/hf_cli_roundtrip.sh`
checks automatically as part of this project's own test suite
(`make integration-test`) - worth running once yourself after any config
change to this server.

## 8. Common problems

**`hf` hangs instead of failing or succeeding.** Almost always a corporate
or sandboxed network proxying `localhost`/your server's address, which
`hf_xet`'s Rust HTTP client doesn't always respect `NO_PROXY` for. Set
`NO_PROXY`/`no_proxy` to include your server's host, or run `hf` from a
network path that doesn't proxy it. See
[Troubleshooting](../README.md#troubleshooting) in the main README for
more detail - this is a client-side networking issue, not a bug in this
server.

**`401 Unauthorized` on every `hf` command.** `xetd` has `-auth-token`/
`$XETD_AUTH_TOKEN` set but `$HF_TOKEN` on the client side is missing,
empty, or doesn't match. Confirm both sides have the exact same value.

**Intermittent `401` near the end of a long download through `xet-proxyd`.**
This is the real Xet CAS rejecting a short-lived xet access token that
expired mid-run (a repo you're otherwise downloading from successfully),
not a proxy auth problem. Since v1.1.0 `xet-proxyd` detects that 401 on the
CAS-facing port, mints a fresh replacement token from the real Hub with the
same client credential, and retries the request once - the download no
longer aborts, and no cached xet token past its `exp` is ever handed out.
If you still see it on an older build, upgrade; re-running `hf download`
always resumes via the `.incomplete` mechanism regardless.

**Uploaded a file, but `hf download` can't find it on a different
machine.** Confirm `HF_ENDPOINT` is set to the same value on both
machines, and that the upload actually succeeded (check the command's own
output, or `hf download myuser/my-model --local-dir /tmp/verify` against
your `HF_ENDPOINT` to confirm the file is really there) - a
silently-failed upload with no local error is the most common cause of
"it's not there on the other end."

**Disk filling up over time.** Every uploaded chunk is retained forever by
default. See
[storage auto-pruning](../README.md#storage-auto-pruning-upload-rate-limiting-dedup-verification-and-persistence)
(`-max-storage-bytes`) if you want old, unused xorbs evicted automatically
once total storage crosses a budget.

## 9. A different kind of mirror: `xet-proxyd` (transparent caching, not manual re-hosting)

Everything above assumes you're deliberately `hf upload`-ing content you
already have onto your own `xetd`. If instead you want a mirror that
**transparently caches whatever real models get requested through it** -
no manual upload step, no deciding in advance what to host - use
`xet-proxyd` instead:

```bash
./bin/xet-proxyd -addr :8420 -hub-addr :8421 -data ./xet-proxy-data \
  -upstream-hub-url https://huggingface.co
```

Use the `:port` form for `-addr`/`-hub-addr` (`:8420`, not
`127.0.0.1:8420`): the default CAS URL this proxy hands out to clients is
built as `http://localhost<addr>`, which is correct for `:8420` but would
mangle an explicit host. For a custom externally-reachable address, pass
`-cas-url http://<host>:<port>` explicitly.

Point `HF_ENDPOINT` at `:8421` exactly like you would for `xetd` - every
`hf download` (and `hf upload`, relayed straight through to the real Hub)
just works, with no repo-by-repo setup. The first time any model is
requested it's fetched from the real huggingface.co; every request after
that is served locally from that cache, including shared-xorb slices
packaged as synthetic xorbs (see 9.1 below). See the main README's
[Caching pull-through proxy](../README.md#caching-pull-through-proxy-xet-proxyd)
section for the full flag reference (rate limiting, cache TTL, the
`-no-cache` pure-relay escape hatch), and its
[Offline handoff](../README.md#offline-handoff-proving-the-point)
subsection for the "huggingface.co is really gone now" story: stop the
proxy, point a plain `xetd` at the exact same `-data` directory, and
what the proxy did cache keeps working, byte-identical, with no proxy
process required. Start that handed-off `xetd` with
`-snapshot-interval 0` for read-only serving: it loads the snapshot once
(which can take tens of seconds for a multi-GB index) and avoids periodic
full rewrites. Only files actually fetched through the proxy are cached;
other sibling files in the same repo are still 404 offline.

Authorization-dependent caches are per-caller: the upstream xet-token
cache is keyed by the caller's credential, repo-info/tree/resolve
freshness is credential-scoped, an upstream 401/403 is never hidden by a
stale entry, and tokens are kept in memory only - never in the `-data`
snapshots.

### 9.1 Partial xorb slices are cached as synthetic xorbs

A file's reconstruction includes `fetch_info` entries giving the byte
ranges **that file needs** from each xorb - not necessarily the whole
xorb. When a file uses only part of one, e.g.

```
url_range = 1108398-1679278  (570,881 bytes)   chunk range = 15-21
```

the proxy has chunks 15-21 of a 1042-chunk xorb. Hashing those cannot
reproduce the whole xorb's hash, so it does not store them under that
hash. It instead repackages the cited chunks as a **new xorb under their
own content hash** and rewrites the file's terms to reference it. That
synthetic xorb is complete and verifiable, so the file keeps working
after the offline handoff - even when the original xorb is shared with
thousands of other files.

A file still falls back to a live relay when `fetch_info` does not cover
every chunk a term cites (an incomplete upstream response). The download
succeeds from the CDN, but that file is not cached; the proxy logs it at
`DEBUG`:

```
DEBUG proxycas: file not cacheable, fetch_info does not cover every term
```

Only the files actually fetched through the proxy are cached. Other
sibling files listed in the same repo's tree are not downloaded and remain
unavailable offline. Non-Xet blobs (a repo's `README.md`, `.gitattributes`,
small CSVs) are relayed live and are not part of the CAS cache at all.
Section 10 is the way to guarantee both cases.
## 10. Building a guaranteed-complete offline library (two-phase)

If your goal is "I want to unplug the network, run a plain `xetd`, and
have all of these files work", this is the guaranteed way. It also covers
non-Xet blobs that section 9.1 says are relayed live, because the
**upload** path has no partial-xorb problem: `hf_xet` chunks the local
file itself and uploads whole xorbs, which `xetd` stores and indexes
completely.

**Phase 1 - download** the repos you want, from the real Hub, to plain
files on disk (no proxy needed):

```bash
unset HF_ENDPOINT                                  # talk to the real Hub
hf download meta-models/Muse-Glimmer-30B-GGUF \
    mmproj-Muse-Glimmer-30B-Q4_K_M.gguf \
    --local-dir ./mirror/Muse-Glimmer-30B-GGUF
```

**Phase 2 - seed** those files into your own `xetd`:

```bash
export HF_ENDPOINT="http://127.0.0.1:8421"         # your xetd's Hub port
hf upload myuser/my-library \
    ./mirror/Muse-Glimmer-30B-GGUF/mmproj-Muse-Glimmer-30B-Q4_K_M.gguf \
    Muse-Glimmer-30B-GGUF/mmproj-Muse-Glimmer-30B-Q4_K_M.gguf
```

After phase 2, `-data` holds complete xorbs plus the reconstruction and
`sha256 -> xet hash` indexes needed to serve those files with no network
at all. Re-running is cheap: identical content uploads **0 new bytes**
(it dedups against what's already stored), so phase 2 is safely
repeatable and interruptible.

This covers **every** file, including the small non-Xet blobs a download
through the proxy relays live (e.g. a repo's `README.md`, `.gitattributes`,
`*_stats.csv`). `xetd`'s preupload negotiates `"lfs"` for every file, so
`hf_xet` Xet-encodes even those small files on upload and they become
offline-servable byte-identically. The only files that must be seeded via
this upload path (rather than the proxy's download cache) are exactly
those non-Xet blobs; the proxy's `-data` alone is a complete offline
library only for the Xet files it cached during download.

Verify the result the honest way - stop the server, restart it, and
download with no upstream configured:

```bash
hf download myuser/my-library Muse-Glimmer-30B-GGUF/mmproj-Muse-Glimmer-30B-Q4_K_M.gguf \
    --local-dir ./offline-check
```

## 11. Windows notes

Everything above works on Windows, with three platform specifics worth
knowing before you start a long mirror run:

**Use a 64-bit Python.** `hf_xet` is a native Rust extension; in a 32-bit
interpreter it exhausts the ~2 GB per-process address space partway
through any file larger than roughly 5 GB and aborts with
`memory allocation of N bytes failed` / exit code `0xC0000409`
(`STATUS_STACK_BUFFER_OVERRUN`). The failure looks like a corrupt download
but is purely an address-space limit. Check with:

```bash
python -c "import struct; print(struct.calcsize('P') * 8, 'bit')"
```

**Clear `HF_TOKEN` before starting a local server.** `xetd` resolves its
own shared secret via `-auth-token`, then `$XETD_AUTH_TOKEN`, then
`$HF_TOKEN` (so a local server "just works" with the token you already
export for the real CLI). The side effect: if `$HF_TOKEN` is set and you
did *not* intend local auth, `xetd` demands that exact token on the CAS
port too - which `hf_xet` cannot present, because it uses the short-lived
xet token the Hub shim minted for it. Every upload then fails with
`401 unauthenticated`. Unless you deliberately want auth:

```powershell
Remove-Item Env:HF_TOKEN -ErrorAction SilentlyContinue
.\bin\xetd.exe -addr :8420 -hub-addr :8421 -data D:\path\to\xet-data
```

**Binaries are `.exe`.** `make build` appends the extension automatically
(via `go env GOEXE`), producing `bin/xetd.exe`, `bin/xet-proxyd.exe`,
`bin/xet.exe`. Invoke them with the extension in scripts; bare `./bin/xetd`
will not resolve.

## What this is not

This is this project's own reimplementation of the Xet CAS + Hub
protocols (see [Where this diverges from real Xet](../README.md#where-this-diverges-from-real-xet)
for the exact, current list of gaps) - not huggingface.co. A plain
`xetd` mirror (sections 1-8 above) has no connection to huggingface.co at
all: nothing you upload is visible there, and nothing there is visible
here, unless you separately mirror it yourself (e.g. `hf download` from
the real Hub, then `hf upload` the same files to your own server with
`HF_ENDPOINT` pointed at each in turn). `xet-proxyd` (section 9) is the
one deliberate exception - by design, it DOES talk to the real
huggingface.co on a cache miss; anything it caches came from a real,
successful request to the real Hub/CAS, not fabricated or copied any
other way.
