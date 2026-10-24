# `github.com/guilt/xet-server/internal/shardformat`

```
package shardformat // import "github.com/guilt/xet-server/internal/shardformat"

Package shardformat implements the on-wire binary layout
of a Xet shard - the file/xorb reconstruction index
real clients upload via POST /v1/shards - ported from
xet_core_structures/src/metadata_shard/{shard_format,file_structs,xorb_structs}.rs.

A shard file is: header, file-info section (one FileDataSequenceHeader + N
FileDataSequenceEntry per file, terminated by a bookend header), xorb-info
section (one XorbChunkSequenceHeader + N XorbChunkSequenceEntry per xorb,
terminated by a bookend header), then three sorted lookup tables (file, xorb,
chunk) mapping a truncated hash to an index into the corresponding content
section, then the footer (read from the end of the file, since it carries the
offsets needed to find everything else).

CONSTANTS

const NoExpiry = ^uint64(0)
    NoExpiry is the ShardKeyExpiry of a shard that never expires: what a client
    writes for its own shards, and what WriteShard uses.


FUNCTIONS

func LookupByKey[E interface{ GetKey() uint64 }](entries []E, key uint64) []E
    LookupByKey returns the byte-index values of all entries whose Key matches
    key. The lookup tables allow duplicate keys (truncated-hash collisions);
    callers should compare full hashes against the referenced content-section
    entry rather than trust a single match.

func SortChunkLookupEntries(entries []ChunkLookupEntry)
    SortChunkLookupEntries sorts entries by Key, matching xet-core's
    `chunk_lookup_combined.sort_unstable_by_key`. BTreeMap iteration in Rust
    already yields file/xorb lookup keys in sorted order (no separate sort
    step there), but chunk entries are collected across all xorbs first and
    explicitly sorted afterward.

func WriteChunkLookupTable(w io.Writer, entries []ChunkLookupEntry) error
func WriteFileDataSequenceEntry(w io.Writer, e FileDataSequenceEntry) error
func WriteFileDataSequenceHeader(w io.Writer, h FileDataSequenceHeader) error
func WriteFileLookupTable(w io.Writer, entries []FileLookupEntry) error
func WriteFileMetadataExt(w io.Writer, e FileMetadataExt) error
func WriteFileVerificationEntry(w io.Writer, e FileVerificationEntry) error
func WriteFooter(w io.Writer, f Footer) error
    WriteFooter writes f's fixed-size wire representation to w.

func WriteHeader(w io.Writer, h Header) error
    WriteHeader writes h's 48-byte wire representation to w.

func WriteXorbChunkSequenceEntry(w io.Writer, e XorbChunkSequenceEntry) error
func WriteXorbChunkSequenceHeader(w io.Writer, h XorbChunkSequenceHeader) error
func WriteXorbLookupTable(w io.Writer, entries []XorbLookupEntry) error

TYPES

type ChunkLookupEntry struct {
	Key        uint64
	XorbIndex  uint32
	ChunkIndex uint32
}
    ChunkLookupEntry maps a truncated chunk hash to (xorb content-section index,
    chunk index within that xorb), mirroring the chunk lookup table's (u64,
    (u32, u32)) pairs.

func ReadChunkLookupTable(r io.Reader, numEntries uint64) ([]ChunkLookupEntry, error)

func (e ChunkLookupEntry) GetKey() uint64

type FileDataSequenceEntry struct {
	XorbHash             merklehash.Hash
	XorbFlags            uint32
	UnpackedSegmentBytes uint32
	ChunkIndexStart      uint32
	ChunkIndexEnd        uint32
}
    FileDataSequenceEntry mirrors file_structs.rs's FileDataSequenceEntry:
    one xorb chunk-range reference within a file's reconstruction sequence.

func ReadFileDataSequenceEntry(r io.Reader) (FileDataSequenceEntry, error)

type FileDataSequenceHeader struct {
	FileHash   merklehash.Hash
	FileFlags  uint32
	NumEntries uint32
}
    FileDataSequenceHeader mirrors file_structs.rs's FileDataSequenceHeader:
    starts one file's entry in the file-info section.

func BookendFileHeader() FileDataSequenceHeader
    BookendFileHeader returns the sentinel FileDataSequenceHeader used to
    terminate the file-info section.

func ReadFileDataSequenceHeader(r io.Reader) (FileDataSequenceHeader, error)

func (h FileDataSequenceHeader) ContainsMetadataExt() bool

func (h FileDataSequenceHeader) ContainsVerification() bool

func (h FileDataSequenceHeader) IsBookend() bool
    IsBookend reports whether h is the all-1s sentinel header xet-core writes to
    terminate the file-info / xorb-info sections for sequential reading.

type FileEntry struct {
	Header       FileDataSequenceHeader
	Entries      []FileDataSequenceEntry
	Verification []FileVerificationEntry // present iff Header.ContainsVerification()
	MetadataExt  *FileMetadataExt        // present iff Header.ContainsMetadataExt()
}
    FileEntry is one file's reconstruction sequence: a header plus its ordered
    xorb-chunk-range references, plus optional per-segment verification entries
    and a metadata_ext (whole-file SHA-256), gated by the corresponding flag
    bits on Header.FileFlags. Real hf_xet clients always set both flags, so a
    reader that ignores them misparses every subsequent byte in the file-info
    section.

type FileLookupEntry struct {
	Key   uint64
	Index uint32
}
    FileLookupEntry / XorbLookupEntry map a truncated hash (Hash.TruncateHash())
    to the byte-index of the corresponding FileDataSequenceHeader /
    XorbChunkSequenceHeader entry within its content section, mirroring the
    (u64, u32) pairs xet-core writes for the file/xorb lookup tables.

func ReadFileLookupTable(r io.Reader, numEntries uint64) ([]FileLookupEntry, error)

func (e FileLookupEntry) GetKey() uint64

type FileMetadataExt struct {
	SHA256 merklehash.Hash // reuses the 32-byte Hash type; not a Merkle hash here, just storage

}
    FileMetadataExt mirrors file_structs.rs's FileMetadataExt: a file's
    plain SHA-256 (distinct from its Xet/Merkle hash), present only when
    FileDataSequenceHeader.ContainsMetadataExt() is true (real hf_xet clients
    always set this flag).

func ReadFileMetadataExt(r io.Reader) (FileMetadataExt, error)

type FileVerificationEntry struct {
	RangeHash merklehash.Hash
}
    FileVerificationEntry mirrors file_structs.rs's FileVerificationEntry:
    one range-hash per file segment, present only when
    FileDataSequenceHeader.ContainsVerification() is true (real hf_xet clients
    always set this flag).

func ReadFileVerificationEntry(r io.Reader) (FileVerificationEntry, error)

type Footer struct {
	Version             uint64
	FileInfoOffset      uint64
	XorbInfoOffset      uint64
	FileLookupOffset    uint64
	FileLookupNumEntry  uint64
	XorbLookupOffset    uint64
	XorbLookupNumEntry  uint64
	ChunkLookupOffset   uint64
	ChunkLookupNumEntry uint64
	ChunkHashHMACKey    merklehash.Hash
	ShardCreationTime   uint64
	ShardKeyExpiry      uint64
	StoredBytesOnDisk   uint64
	MaterializedBytes   uint64
	StoredBytes         uint64
	FooterOffset        uint64 // always last; byte offset of the footer's own start
}
    Footer mirrors MDBShardFileFooter.

func ReadFooter(r io.Reader) (Footer, error)
    ReadFooter reads a fixed-size footer from r.

func WriteKeyedShardExpiring(w io.Writer, xorbs []XorbEntry, key merklehash.Hash, expiry uint64) (Footer, error)
    WriteKeyedShardExpiring serializes an xorb-only shard whose chunk hashes
    are keyed with key, matching xet-core's MDBShardInfo::export_as_keyed_shard
    (DataHash::hmac, the same BLAKE3 keyed hash this package's merklehash
    exposes as Hash.HMAC). The client computes the same keyed hash for each
    chunk it already holds, so it can only match chunks in a response if it has
    the shard's random key. key must be non-zero: a zero key would advertise raw
    chunk hashes to every caller, which is the exact leak this function exists
    to avoid.

func WriteShard(w io.Writer, files []FileEntry, xorbs []XorbEntry) (Footer, error)
    WriteShard serializes files/xorbs into a complete shard file, mirroring
    MDBShardInfo::serialize_from's section order: header, file-info section
    (+ bookend), xorb-info section (+ bookend), file lookup table, xorb lookup
    table, chunk lookup table, footer.

func WriteShardExpiring(w io.Writer, files []FileEntry, xorbs []XorbEntry, expiry uint64) (Footer, error)
    WriteShardExpiring is WriteShard with the footer's ShardKeyExpiry set to
    expiry, a Unix time in seconds. A client's shard cache does not load a
    shard past its expiry (MDBShardFile::load_managed_directory in xet-core
    skips it, and deletes it a week later), so a server that hands out shards
    in global-dedup answers uses this to bound how long a client may keep
    deduplicating against them without asking again - the horizon a garbage
    collector on that server has to respect.

type Header struct {
	Version    uint64
	FooterSize uint64
}
    Header mirrors MDBShardFileHeader.

func DefaultHeader() Header
    DefaultHeader returns the header xet-core writes for new shards.

func ReadHeader(r io.Reader) (Header, error)
    ReadHeader reads and validates a shard header from r.

type Shard struct {
	Header Header
	Footer Footer
	Files  []FileEntry
	Xorbs  []XorbEntry
}
    Shard is the fully decoded contents of a shard file: header, footer,
    and both content sections. Lookup tables are derived (not stored) here since
    a CAS server holds shards in memory and can just linear/binary-search the
    content it already parsed, rather than re-deriving offsets on disk.

func ReadShard(r io.ReadSeeker) (*Shard, error)
    ReadShard parses a complete shard file from r, which must support
    seeking. Real hf_xet clients upload a shard with its footer stripped -
    header.FooterSize reads as 0, and the byte stream ends right after the
    xorb-info section's bookend header (see read_shard_to_bytes_remove_footer
    in xet-core's shard_interface/native.rs) - so this reads the two
    content sections sequentially to EOF in that case, deriving the footer's
    offsets/counts itself rather than trusting a footer that was never sent.
    If header.FooterSize is nonzero (e.g. a shard this package wrote via
    WriteShard), the footer is read from its normal location at EOF instead.

func (s *Shard) FindFile(fileHash merklehash.Hash) (FileEntry, bool)
    FindFile returns the FileEntry for fileHash, or false if not present.
    Linear scan is fine here: a CAS server holds one Shard in memory per upload
    and looks files up by the handful of files in that upload, not across a
    large persisted shard index.

func (s *Shard) FindXorb(xorbHash merklehash.Hash) (XorbEntry, bool)
    FindXorb returns the XorbEntry for xorbHash, or false if not present.

type XorbChunkSequenceEntry struct {
	ChunkHash            merklehash.Hash
	ChunkByteRangeStart  uint32
	UnpackedSegmentBytes uint32
	Flags                uint32
}
    XorbChunkSequenceEntry mirrors xorb_structs.rs's XorbChunkSequenceEntry: one
    chunk's hash, physical position, and uncompressed length within its xorb.

func ReadXorbChunkSequenceEntry(r io.Reader) (XorbChunkSequenceEntry, error)

type XorbChunkSequenceHeader struct {
	XorbHash       merklehash.Hash
	XorbFlags      uint32
	NumEntries     uint32
	NumBytesInXorb uint32
	NumBytesOnDisk uint32
}
    XorbChunkSequenceHeader mirrors xorb_structs.rs's XorbChunkSequenceHeader:
    starts one xorb's entry in the xorb-info section.

func BookendXorbHeader() XorbChunkSequenceHeader
    BookendXorbHeader returns the sentinel XorbChunkSequenceHeader used to
    terminate the xorb-info section.

func ReadXorbChunkSequenceHeader(r io.Reader) (XorbChunkSequenceHeader, error)

func (h XorbChunkSequenceHeader) IsBookend() bool

type XorbEntry struct {
	Header XorbChunkSequenceHeader
	Chunks []XorbChunkSequenceEntry
}
    XorbEntry is one xorb's chunk list within the xorb-info section, mirroring
    xet-core's MDBXorbInfo.

type XorbLookupEntry struct {
	Key   uint64
	Index uint32
}

func ReadXorbLookupTable(r io.Reader, numEntries uint64) ([]XorbLookupEntry, error)

func (e XorbLookupEntry) GetKey() uint64
```
