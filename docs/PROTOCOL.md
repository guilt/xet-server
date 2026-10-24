# Protocol notes: where reality diverges from the spec

This document exists because getting wire compatibility with real
`hf_xet`/xet-core required more than reading the OpenAPI spec and source
comments - several behaviors only surfaced by capturing and replaying
actual bytes from a live `hf_xet` client session, and diverge from what the
documented format implies. If you're changing `casserver`, `hubserver`, or
any of the protocol packages, read this first: reverting one of these to
match the "obvious" spec reading will silently break real-client
compatibility again.

Every finding below has a regression test replaying the real captured
bytes (see `internal/*/testdata/`) - don't delete those fixtures.

## 1. Hashing: BLAKE3-keyed, not SHA-256, with a non-obvious hex encoding

xet-core's `DataHash` (`xet_core_structures::merklehash::data_hash`) is not
a plain SHA-256 or unkeyed BLAKE3 hash. Two distinct keys are used:

- **`DATA_KEY`** - for leaf/chunk hashes (`compute_data_hash`)
- **`INTERNAL_NODE_HASH`** - for interior Merkle-tree nodes
  (`compute_internal_node_hash`)

Both are fed through `blake3::keyed_hash`. `internal/merklehash/datahash.go`
ports both keys verbatim.

**The hex encoding is not a straight byte-to-hex conversion.** `DataHash`
stores its 32 bytes as four little-endian `u64` words in memory
(`[u64; 4]`), and `DataHash::hex()` prints each word as 16 hex digits in
normal (big-endian) digit order - which means each 8-byte group's byte
order is reversed relative to a naive hex-encode of the raw bytes. Every
hash that appears as a JSON string (a `file_id` in a URL, a `hash` field in
a reconstruction response) goes through this transform;
`internal/merklehash/datahash.go`'s `Hex()`/`FromHex()` implement it, and
`TestHex_ByteOrderReferenceVector` in `datahash_test.go` pins it against
xet-core's own test vector - a case chosen specifically because it is *not*
symmetric under a naive whole-buffer hex encode, so a byte-order regression
would fail that test immediately.

By contrast, **hashes stored in a binary format field are raw wire bytes,
no transform** - `write_hash`/`read_hash` in xet-core's
`serialization_utils.rs` just call `m.as_bytes()`. `merklehash.Hash.Bytes()`
/ `FromRawBytes()` are the untransformed accessors used by `xorbformat` and
`shardformat`; `Hex()`/`FromHex()` are only for the JSON/URL-facing side.

**The one field that breaks this rule**: `shardformat.FileMetadataExt.SHA256`
reuses the 32-byte `Hash` type purely for storage (it holds a plain SHA-256,
not a Merkle hash), but real `hf_xet` clients write its wire bytes through
the *same* word-reversal transform as `Hex()` anyway - confirmed by
capturing a real upload and comparing the field's raw bytes against the
file's actual SHA-256 as declared in the commit payload's `lfsFile.oid`:
`Hex()` of the raw bytes equals `lfsFile.oid` exactly; a raw hex encode
(`hex.EncodeToString(h.Bytes())`) does not. `casserver.handleUploadShard`'s
`sha256ToXet` index is therefore keyed by `h.Hex()`, not `h.Bytes()` - the
opposite of what the "raw bytes for binary-format fields" rule above would
suggest, and easy to get backwards (this project did, initially: the
lookup silently missed on every real download until traced back to this).

The Merkle-aggregation algorithm itself (branching factor 4, "natural cut"
when a node's low 64 bits are divisible by 4, salted HMAC for file hashes)
is ported in `internal/merklehash/aggregated_hashes.go` and verified against
reference vectors xet-core's own test suite publishes specifically "to
ensure that other implementations or ports of these functions produce the
correct hashes" (their words, in
`aggregated_hashes.rs::test_correctness`).

## 2. Xorbs are uploaded without a footer

`internal/xorbformat` implements the full `XorbObjectInfoV1` footer format
(chunk hashes, physical/logical boundary offsets, `XETBLOB`/`XBLBHSH`/
`XBLBBND` section idents) - this is the on-disk/cache format xet-core uses
locally. **It is not what gets POSTed to `/v1/xorbs/{prefix}/{hash}`.**

xet-core's `file_upload_session.rs` builds the upload with:

```rust
SerializedXorbObject::from_xorb(xorb, /* serialize_footer = */ false, ...)
```

with the comment directly above it:

> XORBs are sent without footer - the server/client reconstructs it from
> chunk data.

A captured real upload confirmed this exactly: a 500,000-byte file's xorb
upload body was **500,072 bytes total - precisely the sum of 9 chunk
headers + payloads, with zero bytes left over for a footer.** The original
implementation of `casserver.handleUploadXorb` assumed a footer would
follow the last chunk and rejected every real upload with "malformed xorb
footer: EOF."

**The fix**: `handleUploadXorb` now scans chunk headers to EOF via
`xorbformat.ScanChunks`, and for each chunk, decompresses the payload
(per its declared scheme - see #4) and re-hashes the *decompressed* bytes
with `merklehash.ComputeDataHash`. The resulting chunk hash list is
aggregated with `merklehash.XorbHash` and checked against the hash the
client claimed in the URL. The footer the server needs internally
(`xorbformat.FooterV1`, held in `casserver.Server.xorbFooters`) is built
from this scan, never trusted from the wire.

## 3. Shards are uploaded without a footer either - and file headers carry extra flagged sections

Same pattern as xorbs, confirmed the same way: a captured real shard
upload for the same 500,000-byte file was exactly 816 bytes, and walking
the file-info + xorb-info sections by hand (header -> 1 file entry -> bookend
-> 1 xorb entry with 9 chunks -> bookend) landed **exactly** at byte 816 -
zero bytes left for lookup tables or a footer.

The exact source, `xet-core`'s `shard_interface/native.rs`:

```rust
fn read_shard_to_bytes_remove_footer(si: &Arc<MDBShardFile>) -> Result<Bytes> {
    let split_off_index = si.shard.metadata.file_lookup_offset as usize;
    // Read only the portion of the shard file up to the file_lookup_offset,
    // which excludes the footer and lookup sections.
    ...
    header.footer_size = 0;
    ...
}
```

It truncates a normal (footer-having) shard at `file_lookup_offset` - i.e.
right after both content sections' bookend headers - and rewrites the
header's `footer_size` field to `0` before sending.

There's a second, independent gotcha in the file-info section itself: real
clients set **both** `MDB_FILE_FLAG_WITH_VERIFICATION` and
`MDB_FILE_FLAG_WITH_METADATA_EXT` on every file header
(`file_flags = 0xC0000000` in the captured bytes). A reader that ignores
these flag bits reads a fixed-size `FileDataSequenceEntry` array and then
immediately misparses everything after it - the next "header" it reads is
actually a `FileVerificationEntry`, and everything cascades from there.

`shardformat.ReadShard` (via `readShardWithoutFooter`/`readFileInfoSection`)
now:
1. Branches on `header.FooterSize == 0` to decide whether to read
   sequentially to EOF (real client) or seek to a footer at the end (a
   shard this package wrote itself via `WriteShard`, which still uses the
   full self-describing format for local round-trip testing).
2. Reads `FileVerificationEntry`/`FileMetadataExt` conditionally, per
   `FileDataSequenceHeader.ContainsVerification()`/`ContainsMetadataExt()`.

The `FileMetadataExt.SHA256` field is also how `casserver` bridges a
committed file's plain SHA-256 (from the Hub API's commit payload) to its
Xet/Merkle hash - see `casserver.handleUploadShard`'s population of
`sha256ToXet`, and the byte-order note in #1 about why that uses `.Hex()`
rather than `.Bytes()`.

## 4. Real chunk payloads are compressed - with LZ4 (frame format) and, optionally, byte-grouping

Not every chunk uses `CompressionScheme::None`. A capture of a
highly-compressible upload (repeated text, ~900 KB) produced 7 chunks all
tagged `CompressionScheme::LZ4`, compressing to 585 bytes each. Since
verifying a chunk hash requires the *uncompressed* bytes, the server needs
a real decoder - trusting the client's claimed hash for anything except
`CompressionScheme::None` would mean silently skipping verification for
the common case.

Two details matter for building that decoder correctly:

- xet-core uses the **LZ4 frame format** via the Rust `lz4_flex` crate's
  `frame` module - not raw LZ4 blocks. `internal/lz4/frame.go` implements
  frame parsing (magic number, frame descriptor, per-block size headers,
  end mark) on top of `internal/lz4/block.go`'s block decoder, both written
  directly from the public LZ4 format specs (block:
  `lz4_Block_format.md`, frame: `lz4_Frame_format.md`), not ported from any
  existing implementation. `TestDecompressFrame_RealHFXetCapture` replays
  the actual captured LZ4 frame from a real upload and checks the decoded
  text matches.
- `CompressionScheme::ByteGrouping4LZ4` applies a byte-regrouping transform
  *before* LZ4 (regroup bytes by position-mod-4, then compress - exposes
  more redundancy in structured binary data like same-width floats).
  `internal/bg4` implements the reverse transform, verified against a
  published test vector from an independent third-party reference
  implementation, [zig-xet](https://github.com/jedisct1/zig-xet)
  (`src/compression.zig`), rather than xet-core's own Rust source (which
  wasn't read for this specific transform - only its existence was
  confirmed there).

`casserver.decompressChunkPayload` dispatches on the chunk header's
declared scheme to the right decoder before re-hashing.

## 5. Reconstruction must honor Range and return 416 at EOF - not an empty 200

The `GET /v1/reconstructions/{file_id}` handler originally ignored the
`Range` header entirely and always returned the same full-file term list.
This passed every test that only requested a whole small file in one shot
- and then failed on a real 500 KB download with:

```
RuntimeError: Task error: File reconstruction error: Internal Writer Error:
Byte range not sequential: expected start at 500000, got 256000000
```

The cause, traced through `xet_data::file_reconstruction`: `hf_xet` pages
through a file by calling `next_file_terms()` repeatedly, each time
re-requesting reconstruction for a **shifted byte-range window**
(`ReconstructionTermManager::prefetch_block`, sized dynamically based on
throughput). Since the server ignored `Range` and always returned the same
`[0, file_size)` term, the second prefetch call got back byte range
`[0, 500000)` again - but the client's `SequentialWriter` was already
expecting the *next* window to start where the previous one left off, and
saw a wildly different (miscomputed, from the mismatched term) start
offset instead.

The client's own documented contract for "no more data" is a plain HTTP
status, confirmed in `remote_client.rs`'s `get_reconstruction_impl`:

```rust
.with_expected_416()
...
Err(ClientError::ReqwestError(ref e, _))
    if e.status() == Some(StatusCode::RANGE_NOT_SATISFIABLE) => Ok(None),
```

**The fix**: `handleReconstructionV1` now parses the `Range` header (via the
same `parseByteRange` helper the xorb-fetch endpoint uses), clips terms to
the requested window, computes `offset_into_first_range` correctly for a
window that starts mid-term, and returns `416` when `rangeStart >= fileSize`
- exactly the signal real `hf_xet` is waiting for to stop paging.

## 6. The Hub API's xet-token response is a JSON body, not headers-only

`GET /api/{repo_type}s/{repo_id}/xet-{read,write}-token/{revision}` looked
like a pure headers-in/headers-out exchange from `huggingface_hub`'s Python
side: `parse_xet_connection_info_from_headers` reads `X-Xet-Cas-Url`,
`X-Xet-Access-Token`, and `X-Xet-Token-Expiration` straight off the
response headers, and the original `hubserver.handleXetToken` set exactly
those three headers and returned an empty `200` body.

That's the wrong contract for the code path a real `hf upload`/`hf
download` actually exercises. `hf_xet`'s Rust client fetches this same
token via `DirectRefreshRouteTokenRefresher::get_cas_jwt`
(`xet_client::cas_client::auth`), which decodes the response **body** as
JSON into a `CasJWTInfo` struct
(`xet_client::hub_client::types`):

```rust
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CasJWTInfo {
    pub cas_url: String,
    pub exp: u64,
    pub access_token: String,
}
```

An empty body fails that JSON decode. `retry_wrapper.rs`'s
`run_and_extract_json` classifies a decode error as **transient**
(`e.is_decode()` -> `RetryableReqwestError::RetryableError`) and retries
with backoff - so instead of failing fast, `hf upload` just hung,
re-requesting the same token every couple of seconds until the caller's
own timeout eventually killed it. `parse_xet_connection_info_from_headers`
is real code, just for a different caller (the resolve/download metadata
path, which pairs `X-Xet-Hash` with a `Link: rel="xet-auth"` or
`X-Xet-Refresh-Route` header) - not the write/read-token refresh endpoint
`hf_xet`'s upload/download session itself calls.

**The fix**: `handleXetToken` now returns `{"casUrl", "exp",
"accessToken"}` as a JSON body (matching `CasJWTInfo`'s wire format
exactly, camelCase field names included) *in addition to* the `X-Xet-*`
headers, so both call sites are satisfied.

### Minted tokens are bound to one repository

The token the Hub shim mints (and puts on git-lfs actions and signed
xorb URLs) is not just `exp`/`scope`/`subject`: it also carries the repo
type and ID, all inside the HMAC-SHA256 payload (`auth.SignedTokenAuth`,
format `xst2`). A token minted for `alice/sec` cannot be edited into one
for `bob/private`, and every Hub route that names a repo - token minting,
repo info, tree, resolve, preupload, commit, branch, and all git-lfs
batch/object/lock routes - rejects a mismatch with `403`
(`auth.AllowsRepo`). The shared secret itself stays unrestricted (it has
the `admin` scope), and a custom `Authenticator` that does not implement
`auth.RepoScopedPrincipal` keeps its previous unrestricted behavior.

Repo creation is the one route whose target is not already in the URL.
A repo-scoped write token may create only inside its own namespace
(`alice/sec` may create `alice/new`); creating in another namespace
requires the shared secret (`auth.AllowsRepoCreate`). Tokens from the
older unscoped `xst1` format are refused outright rather than accepted
without a repo binding.

The CAS API has no repo in its URLs - xorb and chunk identities are
global and content-addressed - so it authenticates the credential and
signed xorb URL tokens stay bound to the repo that requested them, while
repo authorization for named content happens at the Hub boundary above.

## 7. Never trust a wire-format entry count enough to allocate it upfront

Unlike sections 1-6, this isn't a case where the real client's behavior
diverges from a spec - it's a lesson from fuzzing this project's *own*
implementation of the spec, worth documenting here because the same
mistake is easy to reintroduce in any new wire-format reader.

`shardformat.FileDataSequenceHeader.NumEntries`,
`XorbChunkSequenceHeader.NumEntries`, and the shard footer's three
lookup-table entry counts are all read directly off the wire as a
`uint32`/`uint64` - a real client always writes an honest count matching
what actually follows, but nothing stops a hostile payload from claiming
any value up to that type's maximum. The original readers did
`make([]FileDataSequenceEntry, fh.NumEntries)` (and the equivalent for
every other entry type) *before* reading a single one of those claimed
entries off the wire. A 96-byte payload claiming `NumEntries =
0xFFFFFFFF` (~4.29 billion) - at 48 bytes per `FileDataSequenceEntry` -
forced a single allocation request of **206,158,505,008 bytes (~192
GiB)**, confirmed by temporarily reverting the fix and running the
payload through `ReadShard` directly. Since `POST /v1/shards` requires no
auth and this payload is a fraction of the existing 16 MiB
`maxShardBytes` cap, this was a genuine unauthenticated remote DoS, not a
theoretical one.

The fix, applied everywhere this pattern occurred
(`internal/shardformat/lookup.go`, `internal/shardformat/shard.go`,
`internal/xorbformat/xorbformat.go`'s `ParseFooterV1`): allocate with
`make([]T, 0, cap)` where `cap` is `min(claimedCount,
someSmallPreallocationCeiling)` - a few thousand entries, comfortably
above any realistic real-world shard/xorb - then `append` incrementally
as each entry is actually read off the wire. A dishonest claim now fails
fast the moment the reader hits EOF looking for the next entry that was
never there, having allocated at most the small ceiling's worth of
capacity; an honest, even very large, shard still parses correctly since
`append` grows past the initial capacity exactly as it would for any
other slice.

**The general rule this generalizes to**: any time a wire format lets the
sender declare "there are N of X following," and N determines an upfront
allocation size, N must be either (a) validated against the number of
bytes actually available before allocating, or (b) not trusted for sizing
at all - build the collection incrementally via `append` and let a false
claim fail on the read, not the allocation. `internal/shardformat/dos_test.go`
carries a regression test reproducing the exact payload shape above, and
`internal/shardformat/fuzz_test.go`/`internal/xorbformat/fuzz_test.go`
fuzz the same readers on an ongoing basis specifically to catch a
reintroduction of this class of bug in a new code path.

## 8. Decompression amplification: dedup cannot mitigate a compression bomb

This one came from a direct question worth stating explicitly: **can the
dedup fast-path itself be attacked, or used to make an attack cheaper?**
The answer for this specific shape is no - dedup makes no difference here
at all, because the attack lands *before* dedup is even possible.

`internal/lz4/frame.go`'s `decompressBlockUnknownSize` decompresses one
LZ4 block without knowing its exact decoded size in advance (the LZ4
frame format doesn't store it). The original implementation started from
a size hint and, whenever decompression overflowed the current buffer,
doubled the buffer and retried - with no ceiling. LZ4's block format lets
a single match-length extension sequence (a run of `0xFF` bytes in the
token's length-extension encoding, each worth +255 to the match length -
see `readExtendedLength` in `internal/lz4/block.go`) expand to hundreds of
times its compressed size, entirely independent of any hash or dedup
logic elsewhere in the server.

Measured directly: a ~16 MiB compressed chunk (comfortably inside a
single chunk's 24-bit `CompressedLength` wire field, and far under
`casserver.maxXorbBytes`'s 128 MiB whole-upload cap) decompressed to
**3.8 GB and took ~8 seconds** on ordinary hardware before the fix below.

Why dedup can't help: `casserver.handleUploadXorb` must decompress every
chunk's payload to compute its real content hash
(`merklehash.ComputeDataHash`) and verify it against the xorb hash claimed
in the URL - that decompression happens *before* the server has any hash
to check against `storage.Store.Has`-style existing-key logic. An
attacker re-uploading the identical malicious xorb a thousand times pays
(and forces the server to pay) the full ~8-second decompression cost
every single time; there is no cheaper "we've seen this before" path,
because being able to recognize "we've seen this before" is exactly what
the expensive step produces.

**The fix**: the LZ4 frame format's own frame descriptor declares a
block-max-size code (a 3-bit field mapping to 64 KiB/256 KiB/1 MiB/4 MiB -
see `maxBlockSizeForCode`). A real, spec-compliant LZ4 encoder never
produces a block whose decompressed size exceeds this declared maximum -
it's not a hint, it's a hard guarantee the format makes. Treating it as
just an *initial* sizing guess (and growing past it indefinitely) was the
bug; `decompressBlockUnknownSize` now enforces it as a ceiling, rejecting
any block that grows past it as malformed/hostile. This can only ever
reject a frame that violates the spec's own guarantee - no legitimate
frame is affected. See `internal/lz4/dos_test.go`'s
`TestDecompressFrame_RejectsAmplificationBomb` (reproduces the exact
payload shape, asserts rejection within 2 seconds and bounded heap growth)
and `TestDecompressFrame_LargeBlockUnderCeilingStillWorks` (confirms a
legitimately large block under the ceiling still decodes correctly).

The general lesson, distinct from but complementary to #7's: a format
that lets the *sender* declare a bound on decoded size (here, the frame
descriptor's block-max-size code) should have that bound *enforced* by
the reader, not merely *consulted* as a starting guess. A hint that isn't
also a ceiling gives an attacker exactly the amplification room the
format's own spec was trying to prevent.

## 9. The global chunk-dedup endpoint returns a shard, not a boolean

`GET /v1/chunks/{prefix}/{hash}` (the "does this chunk already exist
anywhere on the server" query - the OpenAPI spec's
`PrefixGlobalDedupeParam` says `prefix` is `default-merkledb`, but the
clients people run send `default`, the xorb prefix, so the server accepts
either) is
easy to misread as a simple existence check returning some JSON boolean
or a `200`/`404` with no body. It isn't - per xet-core's own OpenAPI spec
and its real client implementation
(`RemoteClient::query_for_global_dedup_shard` /
`query_dedup_api` in `xet_client/src/cas_client/remote_client.rs`), a
`200` response body is the **raw bytes of an entire shard** - specifically,
some previously-uploaded shard whose xorb-info section referenced the
queried chunk hash. The real client doesn't parse a small "yes/no plus a
location" response; it downloads that whole shard and calls
`MDBMinimalShard::global_dedup_eligible_chunks` on it (mirrored as
`filter_cas_chunks_for_global_dedup` in xet-core's Rust) to extract every
dedup-eligible chunk hash within it - one dedup query can surface many
chunks the client can skip re-uploading, not just the one it asked about.

This server's implementation (`casserver.handleUploadShard`,
`handleChunkDedup`) mirrors that: every chunk hash referenced by any
uploaded shard's xorb-info section is indexed against that shard's raw
uploaded bytes (`Server.chunkHashToShard`), and a dedup query for a known
chunk hash returns a **complete shard file**, not the uploaded bytes
verbatim. The two are not the same format: an upload has its footer and
lookup tables stripped (`read_shard_to_bytes_remove_footer`), while the
client loads a dedup response with `MDBShardInfo::load_from_reader`,
which seeks to a footer at EOF and requires footer version 1. Serving
uploads back unchanged only ever appeared to work because a client that
uploaded a shard dedups against its own local copy and never fetches it;
the first push from a *second* machine failed with git-xet's "Expected
footer version 1, got 0". A chunk hash no uploaded shard has ever
referenced returns `404`.

The answer is also **keyed, with a fresh random 32-byte key per
response** (`casserver.keyedDedupShard`,
`shardformat.WriteKeyedShardExpiring`). Every chunk hash in the
xorb-info and chunk-lookup sections is `DataHash::hmac(key)` - the same
BLAKE3 keyed hash xet-core's `export_as_keyed_shard` uses - and the key
goes in the footer's `chunk_hash_hmac_key`. A client keying each chunk it
already holds with the footer key matches exactly those chunks; it learns
nothing about raw hashes it does not have. Leaving the key zero (the
pre-fix behavior) exposed the raw hash of every chunk in the matching
xorbs, plus file hashes and reconstruction terms, to any caller holding
one chunk. The answer carries no file-reconstruction entries at all:
clients only need the xorb chunk lists for dedup.

What the answer covers matters as much as its format. A client queries
the first chunk of every file and then at most once per 256 chunks
(`min_spacing_between_global_dedup_queries`), so whatever the first
answer describes is most of what it will ever learn about that file.
An upload shard's xorb-info lists only the xorbs *that upload created*:
after a file is re-uploaded with its first chunk edited, the edit's
shard describes a xorb of one or two chunks, and handing that shard back
for the first-chunk query told a second machine about two chunks while
the file's other xorbs sat on the server; it re-uploaded the rest
(caught by `integration-tests/multi_client_dedup_versions.sh`). The
answer is therefore assembled (`casserver.dedupAnswer`), not looked up:
xorb-info for the xorb the chunk lives in, then every xorb of every
file that references that xorb, in term order, with no file entries -
the same xorb-only shape xet-core's own reference client serves
(`LocalClient::query_for_global_dedup_shard` writes an
`MDBMinimalShard` xorb subset). It is capped at 65536 chunk entries
(about 3 MB; the chunk's own xorb always fits) because the client caches
every answer as a shard file.

That cache is also why the answer's footer carries an expiry
(`shard_key_expiry`, Unix seconds; `casserver.dedupAnswerExpiry`, three
weeks out). The client's `MDBShardFile::load_managed_directory` does
not load a cached shard past its expiry and deletes it a week later, so
the expiry bounds how long a client may keep deduplicating against a
xorb without asking the server again - the same three weeks
(`MDB_SHARD_LOCAL_CACHE_EXPIRATION`) it keeps the shards of its own
uploads. xet-core's reference server writes an expiry the same way
(`LocalClient::query_for_global_dedup_shard`,
`serialize_xorb_subset_with_expiry`). An earlier build of this server
wrote "never", which was harmless only because nothing ever deleted a
xorb; the garbage collector (`xetd gc`, docs/GIT_LFS.md) relies on the
bound and records every xorb an answer lists as accessed at that moment.

## 10. V2 reconstruction is a response-shape optimization, not new data

`GET /v2/reconstructions/{file_id}` (per xet-core's
`api_changes/update_260316_v2_reconstruction_multirange.md` and its real
`QueryReconstructionResponseV2` struct in `xet_client::cas_types`) is easy
to either over-build (assume it needs genuinely different reconstruction
logic) or under-build (assume "multi-range" implies HTTP `multipart/
byteranges` parsing on the server side). Neither is true for a CAS
server: V2 carries exactly the same terms and physical byte ranges V1
does - the only difference is how the *fetch URLs* are packaged.

V1 emits one `fetch_info` entry per term, keyed by xorb hash - if a
file's reconstruction touches the same xorb across several
non-contiguous terms (common for a file that dedups against chunks
scattered across an existing xorb), V1 repeats that xorb's key with
multiple near-identical entries differing only by range. V2's `xorbs`
field groups every range touched for a given xorb under **one**
`XorbMultiRangeFetch` (one URL, a `ranges` list of `{chunks, bytes}`
pairs) - fewer signed URLs to generate and fewer for the client to
request, which matters when a real presigning service rate-limits or
charges per signed URL. `multipart/byteranges` parsing
(`xet_client::cas_client::multipart`) is purely a *client*-side option
(`HF_XET_CLIENT_ENABLE_MULTIRANGE_FETCHING`, default off) for sending one
HTTP request covering multiple ranges instead of one request per range -
nothing a server needs to implement; the server's job is just describing
the ranges, not choosing how the client batches its own requests for
them.

`casserver.handleReconstructionV2` shares `reconstructionWindow` and
`xorbFooterAndPhysicalRange` with `handleReconstructionV1` (see
reconstruction.go) - both compute the exact same per-term physical byte
ranges; V2 only changes how those ranges get packaged into the response,
grouping consecutive ranges for the same xorb hash into one
`XorbMultiRangeFetch` entry rather than emitting a new `fetch_info` entry
per term. `TestReconstructionV2_MatchesV1Data` cross-checks this
directly: it decodes both a V1 and a V2 response for the identical file
and asserts every term and byte range matches exactly, differing only in
how they're grouped.

## 11. Persistence: an atomic snapshot checkpoint, deliberately not a WAL

This section isn't about a real-client wire-format discovery like the
others - it's about a design decision this project made for its own
metadata durability, worth documenting here since it directly affects
what "restart this server" means for anyone operating it.

`casserver.Server` and `hubserver.Server` hold their reconstruction/repo
indices in memory (see [ARCHITECTURE.md](ARCHITECTURE.md)'s design
decisions). Two ways to make that survive a restart were considered:

- **A write-ahead log**: append every mutation (a xorb upload, a shard
  upload, a commit) to a log file, replay it on startup. Crash-safe up to
  the last fsync'd entry, but needs correct compaction (the log grows
  forever otherwise) and correct replay logic - real complexity to get
  right, for a project whose bulk data (xorb bytes) is already durable in
  `storage.Store` regardless of which approach wins; only the metadata
  indices are at stake.
- **A periodic atomic snapshot** (what this project implements,
  `Server.Snapshot`/`LoadSnapshot` in both packages): serialize every
  index to JSON, write it to a temp file, `os.Rename` it into place - the
  exact same stage-then-rename pattern `storage/fsstore.Store.Put` already
  uses so a reader never observes a half-written result. Simple, no new
  dependency, easy to reason about. The real cost: **anything written
  between two snapshots is lost if the process is killed** (not just on a
  graceful exit) - a hard crash, an OOM kill, `kill -9`, or a power loss
  between checkpoints loses whatever mutations happened in that window.

This project chose the snapshot approach. The tradeoff is real and worth
stating plainly: this is a periodic checkpoint, not a durability
guarantee for every individual write. `cmd/xetd`'s `-snapshot-interval`
flag (default 1 minute) controls how large that window is; a graceful
shutdown (`SIGINT`/`SIGTERM`, handled via `signal.NotifyContext` in
`cmd/xetd/main.go`) always takes one final snapshot before exiting, so
the only real exposure is an *un*graceful termination. For a single-node
development/internal server - this project's stated scope - that's an
acceptable tradeoff in exchange for not needing WAL compaction/replay
correctness; a deployment that needs stronger durability guarantees
should either shorten `-snapshot-interval` or treat this as a signal that
a real database is a better fit than this project's in-memory-plus-
checkpoint model.

One consequence worth calling out for anyone reading `casserver`'s
snapshot code: `Snapshot()` takes each index's own mutex only briefly (one
`RLock`/copy/`RUnlock` per index, not one lock held across the whole
operation), so the resulting file is not perfectly instant-consistent
across every index simultaneously - a xorb upload completing between two
of those per-index locks could show up in one section of the snapshot but
not another. This is intentional, not an oversight: no code path anywhere
in either server ever reads more than one index under a combined
invariant (the same reasoning behind splitting the mutexes into
per-index/per-repo locks in the first place - see ARCHITECTURE.md), so a
snapshot that isn't perfectly atomic *across* indices restores to a state
no different from "a few requests landed slightly before or after this
particular snapshot" - true of any periodic checkpoint regardless of
locking strategy.

### 11.1 Snapshot v2: shard bodies are stored once, not once per chunk

The chunk-dedup index (`chunkHashToShard`, backing
`GET /v1/chunks/{prefix}/{hash}` - see section 9) maps **every chunk hash
in a shard** to the shard bytes that describe it. Storing the shard body
directly as each entry's value is the obvious implementation, and it is
what snapshot v1 serialized:

```go
chunkHashToShard map[merklehash.Hash][]byte   // v1: one copy PER CHUNK
```

In memory that's cheap - every entry is the same backing slice. In JSON it
is catastrophic: `encoding/json` has no notion of aliasing, so it emits
the full shard body once for every chunk that references it. A single real
model produces a ~30 MB shard covering ~1.7 M chunks, which serializes to
roughly **50 TB**; in practice the snapshot goroutine exhausted memory and
took the process down with `fatal error: out of memory` about a minute
after start, every time.

Snapshot v2 stores each shard body once, content-addressed, and points
chunks at it:

```go
chunkHashToShard map[merklehash.Hash]merklehash.Hash  // chunk -> shard content hash
shardBodies      map[merklehash.Hash][]byte           // shard content hash -> body
```

Serialized size becomes O(unique shards + chunks) instead of
O(shards x chunks). Keying `shardBodies` by `ComputeDataHash(body)` also
means an identical shard uploaded twice collapses to one entry for free.

Two operational notes follow from this:

- **A version bump invalidates the affected index, and that must not be
  fatal.** `LoadSnapshot` reads the `version` field first and, on any
  mismatch, logs a warning and starts with empty indices rather than
  returning an error. Returning an error here would mean a server that
  refuses to start after an upgrade until someone deletes the snapshot by
  hand - a restart loop triggered by a routine format change. Xorb bytes
  live in `storage.Store`, not the snapshot, so the only cost of starting
  fresh is re-deriving metadata as clients touch each repo again.
- **This bug hid a second one.** While every snapshot attempt was dying,
  nothing was being checkpointed at all - including `fileRecon`, the
  index that makes offline reconstruction possible. The data directory
  looked fine (xorb bytes were all present and correct on disk) but a
  restarted server could not reconstruct a single file from them. If you
  are debugging "the bytes are there but nothing downloads after a
  restart", check that snapshots are actually completing before looking
  anywhere else.


## 12. The real Hub's CAS: presigned CDN URLs, no `/v1/xorbs/` GET, and strict Content-Type

The proxy findings in this section were discovered by pointing `xet-proxyd`
at the **real** huggingface.co (a local 32-bit build of `hf_xet` driving the
real `hf` CLI through it), not at this project's own stand-in servers. Each
one is a real behavioral difference between this project's local CAS/Hub
shims and the production service that a proxy must bridge.

### 12.1 Resolve HEAD is a 302 with the Xet metadata on the redirect itself

`HEAD /{repo_id}/resolve/{revision}/{filename}` for a Xet file returns a
`302` whose `Location` points at the CDN (`us.aws.cdn.hf.co/...`) and whose
headers carry `X-Xet-Hash`, `X-Linked-Size`, `X-Linked-Etag`. The CDN's
`200` (after following the redirect) has none of them. `huggingface_hub`
reads the metadata from the `302` (`allow_redirects=False`,
`follow_relative_redirects=True`); `hfclient.Resolve` now does the same:
same-origin (relative, e.g. the `/api/resolve-cache/...` hop a non-Xet file
takes) redirects are followed, cross-origin ones are returned as-is, and
the metadata is read from whichever response the client lands on.

### 12.2 The real CAS does not serve xorb bytes over `GET /v1/xorbs/`

The production CAS server's `/v1/xorbs/{prefix}/{hash}` endpoint answers
`Allow: HEAD, POST` - no `GET`. Xorb bytes are obtained exclusively via the
**presigned CDN URLs** in a reconstruction response's `fetch_info` (V1:
`fetch_info[xorbHash] = [{url, url_range, range}]`; V2: `xorbs[xorbHash] =
[{url, ranges}]`). Each presigned URL is scoped to a byte range
(`url_range`, both ends inclusive - fetch it with `Range: bytes={start}-{end}`),
and the reconstruction response covers only the byte ranges the **requested
file** needs. For a normally-varying file that is the full xorb; for a
globally-deduped/shared xorb only a slice (a file made entirely of one
repeated chunk is the degenerate case). The proxy repackages each cited
slice as a new xorb under its own content hash and rewrites the file's
terms to reference it, so the slice is offline-capable without ever being
stored under a hash it does not match - see ARCHITECTURE.md's partial-xorb
section. If `fetch_info` does not cover every chunk a term cites, the
proxy relays that file live instead of caching it. This project's own
`casserver` still serves `GET /v1/xorbs/` (its local integration stand-in
role), so `proxycas.ensureFileReconCached` prefers the presigned URLs when
`fetch_info` is present and falls back to the direct fetch otherwise.

### 12.3 Every Hub/CAS write needs an explicit Content-Type

The real Hub is FastAPI-based: a JSON body without `Content-Type:
application/json` is not parsed at all, so every field reads as
"undefined" - create-repo failed with `expected string, received undefined`
on its `name` field, preupload on `files[0].sample`. Commit sends ndjson
(`Content-Type: application/x-ndjson`, matching `huggingface_hub`), and CAS
xorb/shard uploads need `application/octet-stream` (per xet-core's
`openapi/cas.openapi.yaml`).

### 12.4 Error responses are relayed verbatim

`create_repo` under `exist_ok=True` tolerates a `409` by reading the
`url` field off the response body. A proxy that relays the upstream
status but writes its own `{"error": ...}` body breaks that (`KeyError:
'url'`), so `writeUpstreamError` relays the real upstream error body
verbatim.

### 12.5 Write bodies are forwarded verbatim

Preupload bodies carry a per-file `sample` field and commit bodies are
ndjson LFS-pointer lines; a decode-and-reencode drops fields the real Hub
requires, so `proxyhub` relays both request bodies (and their responses)
verbatim, parsing only a copy for the local ingest bookkeeping.

### 12.6 Git LFS and inline (non-Xet) traffic passes through

Small/non-Xet files upload/download through the Git LFS wire protocol
(`/{repo}.git/info/lfs/objects/batch`, `/{repo}.git/objects/...`), which
`xet-proxyd` relays live to the real Hub so `hf upload`/`hf download` of
such files still works through the proxy (no caching - the offline
handoff only covers Xet files). The same applies to a non-Xet file reached
through the plain `/{repo_id}/resolve/{revision}/{filename}` URL: such a
file has no `X-Xet-Hash`, and the embedded `hubserver`'s resolve handler
can only serve Xet files (it answers via CAS reconstruction data keyed by
a Xet hash), so `proxyhub` detects the missing `X-Xet-Hash` upstream and
relays the resolve live instead of serving a CAS-backed 404. A plain
`xetd` on the proxy's `-data` therefore cannot serve these files offline
on its own - but the two-phase seed flow (MIRRORING.md section 10) covers
them: `xetd`'s preupload negotiates `"lfs"` for every file, so the upload
Xet-encodes even these small blobs and they become offline-servable
byte-identically. Note that `xetd` *does* implement the batch endpoint,
for the reason in section 13.

## 13. The LFS batch endpoint is the entry point to the Xet upload path

The most surprising thing about uploading a large file with `hf_xet`
installed: the client does **not** start on a Xet-specific endpoint. It
starts with a plain Git LFS batch request, and it is the *server's reply*
that decides whether the Xet path is taken at all.

`huggingface_hub`'s `_upload_files` (in `_commit_api.py`) offers the
server a transfer list and branches on what comes back:

```python
transfers = ["basic", "multipart"]
if is_xet_available():
    transfers.append("xet")
actions, errors, chosen = post_lfs_batch_info(..., transfers=transfers)
if chosen == "xet" and "xet" in transfers:
    xet_additions.extend(chunk_list)   # -> _upload_xet_files
else:
    lfs_actions.extend(actions_chunk)  # -> plain LFS upload
```

So a server that does not answer
`POST /{repo_id}.git/info/lfs/objects/batch` gets no Xet upload traffic at
all - the client falls back to plain LFS, hits whatever that endpoint does
(a 404 here), and the upload fails. The real Hub's reply for a Xet-enabled
repo is minimal:

```json
{ "transfer": "xet",
  "objects": [ { "oid": "<sha256>", "size": 12586448320 } ] }
```

`oid` and `size` echo the request; per-object `actions` are absent, which
`_validate_batch_actions` explicitly tolerates (it requires only `oid` and
`size`) and which the Xet path ignores entirely - it re-derives everything
from a `xet-write-token` plus the local file. `hubserver` therefore
implements this endpoint to return exactly that shape.

Why this is easy to miss: files below `huggingface_hub`'s LFS threshold
(~5 MB) are committed inline as regular git blobs and never touch the
batch endpoint, so a small-file round-trip test passes against a server
that has no batch endpoint at all. The gap only appears once a test file
crosses the threshold.

### 13.1 Hardening: this endpoint echoes caller input

Two properties make the batch endpoint worth bounding more carefully than
its size suggests. It sits in front of the entire upload path with only a
write-scope check, and its response **echoes back** the `oid`/`size` pairs
the caller supplied. That echo is an amplification primitive: a compact
request listing a large number of tiny oids costs almost nothing to send
but forces a proportional allocation server-side and a considerably larger
reply. `hubserver` therefore applies three bounds, all of which reject
rather than truncate (silently dropping objects would leave the client
believing files were negotiated that never were):

- `maxLFSBatchBytes` (4 MB) via `http.MaxBytesReader`, so the body cannot
  be streamed unbounded into `json.Decode`. Oversize reports `413`, not a
  misleading `400 invalid JSON`.
- `maxLFSBatchObjects` (4096). Real clients chunk at 256 per batch
  (`UPLOAD_BATCH_MAX_NUM_FILES`), leaving a 16x margin.
- Repo state is only created *after* the request validates. Otherwise a
  flood of malformed requests bearing random repo IDs would grow the
  server's repo map without ever submitting a valid batch.

One further subtlety, found by fuzzing rather than review:
`json.Decoder.Decode` reads the first JSON value and **silently ignores
whatever follows**, so `{"operation":"upload"}` followed by arbitrary
trailing bytes was accepted as a well-formed batch. (Go's decoder also
matches field names case-insensitively, so `operAtion` binds too.) Lenient
trailing-data handling is how two intermediaries end up disagreeing about
what a request said, so the body must now decode to exactly one JSON
value - a second `Decode` has to return `io.EOF`. Trailing whitespace
still qualifies, so a trailing newline is fine.

## 14. `repo-info` must return `siblings`, or whole-repo downloads break

`snapshot_download` - what `hf download` uses whenever more than one
filename is involved - reads the file list from `repo_info(...).siblings`
and falls back to `list_repo_tree` when that list is empty:

```python
repo_files = [f.rfilename for f in repo_info.siblings] if repo_info.siblings is not None else []
unreliable_nb_files = (repo_info.siblings is None or len(repo_info.siblings) == 0 or ...)
if unreliable_nb_files:
    repo_files = (f.rfilename for f in api.list_repo_tree(...))   # a GENERATOR
```

That fallback path is subtly broken downstream, and not in this project's
code: the generator is passed to `tqdm.contrib.concurrent.thread_map`,
whose `_min_map_len` does

```python
min(n for it in iterables if (n := length_hint(it, -1)) >= 0)
```

A generator's `length_hint` is `-1`, so every candidate is filtered out
and `min()` raises **`ValueError: min() arg is an empty sequence`** -
before a single file is fetched. The tree listing itself is fine; merely
*taking the fallback* is fatal.

The fix is to make the fallback unnecessary by returning a non-empty
`siblings` array from
`GET /api/{repo_type}s/{repo_id}/revision/{revision}`:

```json
{ "id": "...", "sha": "main", "private": false,
  "siblings": [ { "rfilename": "model.gguf" }, { "rfilename": "config.json" } ] }
```

Only `rfilename` is needed. `hubserver` populates it from the revision's
known files, and `proxyhub` both relays upstream's list and ingests each
entry so a later cache-served response carries it too.

The tree listing itself interleaves real files with directory entries
(`type: "directory"`, size 0) and `huggingface_hub` builds a `RepoFile`
only for `type == "file"` (`RepoFolder` otherwise), with `snapshot_download`
downloading every `RepoFile`. A directory that comes back typed as a file
is therefore downloaded - and 404s on resolve. `proxyhub` drops non-file
entries when ingesting a tree into its embedded `hubserver` (whose flat
file model would re-emit them as `"type": "file"`), so directories are
never handed to the client as downloadable files.

## 15. Resolve URLs carry a repo-type prefix - except for models

The `/api/` namespace is uniformly typed (`/api/models/...`,
`/api/datasets/...`, `/api/spaces/...`), so it is natural to assume resolve
URLs match. They do not - models are the unprefixed special case:

```
models    {namespace}/{name}/resolve/{revision}/{filename}
datasets  datasets/{namespace}/{name}/resolve/{revision}/{filename}
spaces    spaces/{namespace}/{name}/resolve/{revision}/{filename}
```

Parsing these left-to-right on a fixed segment index makes every dataset
and space 404, because the index that holds `resolve` for a model holds
the repo *name* for a dataset. Both `hubserver` and `proxyhub` instead
locate the `/resolve/` marker and take the two segments immediately before
it as `{namespace}/{name}`, treating anything further left as the
repo-type prefix. That is robust to a prefix this project hasn't seen, and
it degrades to `model` when there is none.

Two knock-on details, both of which produce confusing failures if missed:

- **The upstream call must carry the prefix too.** Resolving a dataset at
  the bare model URL makes the real Hub answer `404 RepositoryNotFound` -
  it looked for a *model* by that name. `hfclient.Resolve` takes
  `repoType` and prefixes accordingly.
- **`X-Xet-Refresh-Route` must be typed.** That header tells the client
  where to re-mint an expiring token mid-download. It lives under `/api/`,
  so it always carries a pluralized type: a dataset's refresh route is
  `/api/datasets/{repo_id}/xet-read-token/{revision}`. Hardcoding `models`
  there works right up until the first token expiry inside a long
  download, then fails against a model that doesn't exist.

## 16. Newer clients POST shards to `/shards` and dedup under `default`

Driving a real `git push` through git-xet 0.2.1 (xet-core 1.6) against
this server showed two requests the openapi spec does not describe:

    GET  /v1/chunks/default/<chunk hash>    -> was 400 "unsupported chunk-dedup prefix"
    POST /shards                            -> was 404

`cas_client/src/remote_client.rs` at that tag builds the dedup key with
`PREFIX_DEFAULT` (`"default"`, the same prefix as xorb uploads) even
though `openapi/cas.openapi.yaml` still says the only acceptable dedup
prefix is `default-merkledb`, and `upload_shard` formats
`"{endpoint}/shards"` with no version segment while the spec lists
`/v1/shards`. The client treats a failed dedup query as "no dedup
available" and carries on (so the first symptom was silent loss of
cross-push dedup), but the shard 404 fails the push outright.

Both are now served: `/shards` is mounted at the CAS mux root next to
`/v1/shards`, and `handleChunkDedup` accepts either prefix. Older clients
that use the documented paths are unaffected.

## How these were found: capture, don't guess

Every fix above came from the same loop, not from re-reading the spec more
carefully:

1. Point `hf_xet`'s low-level `XetSession` Python API directly at a local
   `casserver` instance (`endpoint=` kwarg - no Hub API needed for this
   step).
2. Run a real upload/download and read the actual error. Run `xetd` with
   `DEBUG=1` alongside this to log every request it receives (method,
   path, status, duration) plus commit/shard/resolve lookup details - the
   #3 and #6 findings above were both traced this way: a request that
   *should* have hit the CAS server (e.g. `POST /v1/xorbs/...`) never
   showed up in the debug log at all, which pointed straight at the Hub
   API step just before it instead of anywhere in the CAS path.
3. When the error was opaque (e.g. a byte-count mismatch), insert a
   capturing HTTP proxy between the client and the server to record the
   exact raw request bytes.
4. Hand-parse the captured bytes against the expected struct layout, byte
   offset by byte offset, until the actual layout became obvious.
5. Cross-reference the real xet-core source once the shape was known, to
   confirm *why* (not just *that*) the real format differs, and to find the
   exact comment/function explaining it.
6. Fix the Go implementation, then commit the captured bytes as a
   `testdata/` regression fixture so the bug can't silently return.

If you hit a new wire-compatibility gap, follow the same loop - the
`internal/casserver/testdata/`, `internal/lz4/testdata/`, and
`internal/shardformat/testdata/` fixtures already checked in were all
produced this way, and are a good reference for how to capture and encode
a new one.
