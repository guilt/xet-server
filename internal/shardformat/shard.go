package shardformat

import (
	"errors"
	"io"

	"github.com/guilt/xet-server/internal/merklehash"
)

// FileEntry is one file's reconstruction sequence: a header plus its
// ordered xorb-chunk-range references, plus optional per-segment
// verification entries and a metadata_ext (whole-file SHA-256), gated by
// the corresponding flag bits on Header.FileFlags. Real hf_xet clients
// always set both flags, so a reader that ignores them misparses every
// subsequent byte in the file-info section.
type FileEntry struct {
	Header       FileDataSequenceHeader
	Entries      []FileDataSequenceEntry
	Verification []FileVerificationEntry // present iff Header.ContainsVerification()
	MetadataExt  *FileMetadataExt        // present iff Header.ContainsMetadataExt()
}

// XorbEntry is one xorb's chunk list within the xorb-info section,
// mirroring xet-core's MDBXorbInfo.
type XorbEntry struct {
	Header XorbChunkSequenceHeader
	Chunks []XorbChunkSequenceEntry
}

// Shard is the fully decoded contents of a shard file: header, footer, and
// both content sections. Lookup tables are derived (not stored) here since
// a CAS server holds shards in memory and can just linear/binary-search
// the content it already parsed, rather than re-deriving offsets on disk.
type Shard struct {
	Header Header
	Footer Footer
	Files  []FileEntry
	Xorbs  []XorbEntry
}

// WriteShard serializes files/xorbs into a complete shard file, mirroring
// MDBShardInfo::serialize_from's section order: header, file-info section
// (+ bookend), xorb-info section (+ bookend), file lookup table, xorb
// lookup table, chunk lookup table, footer.
func WriteShard(w io.Writer, files []FileEntry, xorbs []XorbEntry) (Footer, error) {
	return WriteShardExpiring(w, files, xorbs, NoExpiry)
}

// NoExpiry is the ShardKeyExpiry of a shard that never expires: what a
// client writes for its own shards, and what WriteShard uses.
const NoExpiry = ^uint64(0)

// WriteShardExpiring is WriteShard with the footer's ShardKeyExpiry set
// to expiry, a Unix time in seconds. A client's shard cache does not
// load a shard past its expiry (MDBShardFile::load_managed_directory in
// xet-core skips it, and deletes it a week later), so a server that
// hands out shards in global-dedup answers uses this to bound how long
// a client may keep deduplicating against them without asking again -
// the horizon a garbage collector on that server has to respect.
func WriteShardExpiring(w io.Writer, files []FileEntry, xorbs []XorbEntry, expiry uint64) (Footer, error) {
	return writeShard(w, files, xorbs, nil, expiry)
}

// WriteKeyedShardExpiring serializes an xorb-only shard whose chunk hashes
// are keyed with key, matching xet-core's MDBShardInfo::export_as_keyed_shard
// (DataHash::hmac, the same BLAKE3 keyed hash this package's merklehash
// exposes as Hash.HMAC). The client computes the same keyed hash for each
// chunk it already holds, so it can only match chunks in a response if it
// has the shard's random key. key must be non-zero: a zero key would
// advertise raw chunk hashes to every caller, which is the exact leak this
// function exists to avoid.
func WriteKeyedShardExpiring(w io.Writer, xorbs []XorbEntry, key merklehash.Hash, expiry uint64) (Footer, error) {
	if key.IsZero() {
		return Footer{}, errors.New("shardformat: refusing to write a shard with a zero chunk-hash key")
	}
	return writeShard(w, nil, xorbs, &key, expiry)
}

func writeShard(w io.Writer, files []FileEntry, xorbs []XorbEntry, chunkKey *merklehash.Hash, expiry uint64) (Footer, error) {
	var buf countingWriter
	cw := io.MultiWriter(w, &buf)

	if err := WriteHeader(cw, DefaultHeader()); err != nil {
		return Footer{}, err
	}

	footer := Footer{}
	if chunkKey != nil {
		footer.ChunkHashHMACKey = *chunkKey
	}
	footer.FileInfoOffset = buf.n

	var fileLookup []FileLookupEntry
	var fileIndex uint32
	for _, f := range files {
		fileLookup = append(fileLookup, FileLookupEntry{Key: f.Header.FileHash.TruncateHash(), Index: fileIndex})

		header := f.Header
		if len(f.Verification) > 0 {
			header.FileFlags |= fileFlagVerification
		}
		if f.MetadataExt != nil {
			header.FileFlags |= fileFlagMetadataExt
		}
		if err := WriteFileDataSequenceHeader(cw, header); err != nil {
			return Footer{}, err
		}
		for _, e := range f.Entries {
			if err := WriteFileDataSequenceEntry(cw, e); err != nil {
				return Footer{}, err
			}
		}
		numInfoEntries := uint32(len(f.Entries))
		if len(f.Verification) > 0 {
			for _, v := range f.Verification {
				if err := WriteFileVerificationEntry(cw, v); err != nil {
					return Footer{}, err
				}
			}
			numInfoEntries += uint32(len(f.Verification))
		}
		if f.MetadataExt != nil {
			if err := WriteFileMetadataExt(cw, *f.MetadataExt); err != nil {
				return Footer{}, err
			}
			numInfoEntries++
		}
		fileIndex += 1 + numInfoEntries
	}
	if err := WriteFileDataSequenceHeader(cw, BookendFileHeader()); err != nil {
		return Footer{}, err
	}

	footer.XorbInfoOffset = buf.n

	var xorbLookup []XorbLookupEntry
	var chunkLookup []ChunkLookupEntry
	var xorbIndex uint32
	for _, x := range xorbs {
		xorbLookup = append(xorbLookup, XorbLookupEntry{Key: x.Header.XorbHash.TruncateHash(), Index: xorbIndex})
		if err := WriteXorbChunkSequenceHeader(cw, x.Header); err != nil {
			return Footer{}, err
		}
		for i, c := range x.Chunks {
			chunkHash := c.ChunkHash
			if chunkKey != nil {
				chunkHash = chunkHash.HMAC(*chunkKey)
			}
			entry := c
			entry.ChunkHash = chunkHash
			if err := WriteXorbChunkSequenceEntry(cw, entry); err != nil {
				return Footer{}, err
			}
			chunkLookup = append(chunkLookup, ChunkLookupEntry{
				Key: chunkHash.TruncateHash(), XorbIndex: xorbIndex, ChunkIndex: uint32(i),
			})
		}
		xorbIndex += 1 + uint32(len(x.Chunks))
	}
	if err := WriteXorbChunkSequenceHeader(cw, BookendXorbHeader()); err != nil {
		return Footer{}, err
	}

	footer.FileLookupOffset = buf.n
	footer.FileLookupNumEntry = uint64(len(fileLookup))
	if err := WriteFileLookupTable(cw, fileLookup); err != nil {
		return Footer{}, err
	}

	footer.XorbLookupOffset = buf.n
	footer.XorbLookupNumEntry = uint64(len(xorbLookup))
	if err := WriteXorbLookupTable(cw, xorbLookup); err != nil {
		return Footer{}, err
	}

	SortChunkLookupEntries(chunkLookup)
	footer.ChunkLookupOffset = buf.n
	footer.ChunkLookupNumEntry = uint64(len(chunkLookup))
	if err := WriteChunkLookupTable(cw, chunkLookup); err != nil {
		return Footer{}, err
	}

	footer.FooterOffset = buf.n
	footer.ShardKeyExpiry = expiry
	if err := WriteFooter(cw, footer); err != nil {
		return Footer{}, err
	}

	return footer, nil
}

// ReadShard parses a complete shard file from r, which must support
// seeking. Real hf_xet clients upload a shard with its footer stripped -
// header.FooterSize reads as 0, and the byte stream ends right after the
// xorb-info section's bookend header (see
// read_shard_to_bytes_remove_footer in xet-core's
// shard_interface/native.rs) - so this reads the two content sections
// sequentially to EOF in that case, deriving the footer's offsets/counts
// itself rather than trusting a footer that was never sent. If
// header.FooterSize is nonzero (e.g. a shard this package wrote via
// WriteShard), the footer is read from its normal location at EOF instead.
func ReadShard(r io.ReadSeeker) (*Shard, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	header, err := ReadHeader(r)
	if err != nil {
		return nil, err
	}

	if header.FooterSize == 0 {
		return readShardWithoutFooter(r, header)
	}
	return readShardWithFooter(r, header)
}

// readShardWithoutFooter reads the file-info and xorb-info content
// sections sequentially from r's current position (immediately after the
// header) through to EOF, with no footer or lookup tables present on the
// wire.
func readShardWithoutFooter(r io.ReadSeeker, header Header) (*Shard, error) {
	s := &Shard{Header: header}

	files, err := readFileInfoSection(r)
	if err != nil {
		return nil, err
	}
	s.Files = files

	xorbs, err := readXorbInfoSection(r)
	if err != nil {
		return nil, err
	}
	s.Xorbs = xorbs

	return s, nil
}

// readShardWithFooter reads a shard that carries a real footer (offsets
// for both content sections plus the three lookup tables), as produced by
// this package's own WriteShard.
func readShardWithFooter(r io.ReadSeeker, header Header) (*Shard, error) {
	if _, err := r.Seek(-int64(footerSize), io.SeekEnd); err != nil {
		return nil, err
	}
	footer, err := ReadFooter(r)
	if err != nil {
		return nil, err
	}

	s := &Shard{Header: header, Footer: footer}

	if _, err := r.Seek(int64(footer.FileInfoOffset), io.SeekStart); err != nil {
		return nil, err
	}
	files, err := readFileInfoSection(r)
	if err != nil {
		return nil, err
	}
	s.Files = files

	if _, err := r.Seek(int64(footer.XorbInfoOffset), io.SeekStart); err != nil {
		return nil, err
	}
	xorbs, err := readXorbInfoSection(r)
	if err != nil {
		return nil, err
	}
	s.Xorbs = xorbs

	return s, nil
}

// maxSectionEntryPreallocate caps upfront allocation capacity for a
// file's/xorb's entry list, for the same reason as
// lookup.go's maxLookupEntryPreallocate: fh.NumEntries/xh.NumEntries are
// attacker-controlled uint32 wire fields, and a tiny malicious shard
// claiming NumEntries near uint32's max must not force a multi-gigabyte
// allocation before any of those claimed entries have actually been read
// off the wire. append still lets a genuinely large, honest section grow
// past this cap.
const maxSectionEntryPreallocate = 4096

// readFileInfoSection reads FileDataSequenceHeader+entries records from r's
// current position until the bookend header, per file.
func readFileInfoSection(r io.Reader) ([]FileEntry, error) {
	var files []FileEntry
	for {
		fh, err := ReadFileDataSequenceHeader(r)
		if err != nil {
			return nil, err
		}
		if fh.IsBookend() {
			return files, nil
		}
		entries := make([]FileDataSequenceEntry, 0, min(uint64(fh.NumEntries), maxSectionEntryPreallocate))
		for i := uint32(0); i < fh.NumEntries; i++ {
			e, err := ReadFileDataSequenceEntry(r)
			if err != nil {
				return nil, err
			}
			entries = append(entries, e)
		}

		fe := FileEntry{Header: fh, Entries: entries}
		if fh.ContainsVerification() {
			verification := make([]FileVerificationEntry, 0, min(uint64(fh.NumEntries), maxSectionEntryPreallocate))
			for i := uint32(0); i < fh.NumEntries; i++ {
				v, err := ReadFileVerificationEntry(r)
				if err != nil {
					return nil, err
				}
				verification = append(verification, v)
			}
			fe.Verification = verification
		}
		if fh.ContainsMetadataExt() {
			ext, err := ReadFileMetadataExt(r)
			if err != nil {
				return nil, err
			}
			fe.MetadataExt = &ext
		}

		files = append(files, fe)
	}
}

// readXorbInfoSection reads XorbChunkSequenceHeader+entries records from
// r's current position until the bookend header, per xorb.
func readXorbInfoSection(r io.Reader) ([]XorbEntry, error) {
	var xorbs []XorbEntry
	for {
		xh, err := ReadXorbChunkSequenceHeader(r)
		if err != nil {
			return nil, err
		}
		if xh.IsBookend() {
			return xorbs, nil
		}
		chunks := make([]XorbChunkSequenceEntry, 0, min(uint64(xh.NumEntries), maxSectionEntryPreallocate))
		for i := uint32(0); i < xh.NumEntries; i++ {
			c, err := ReadXorbChunkSequenceEntry(r)
			if err != nil {
				return nil, err
			}
			chunks = append(chunks, c)
		}
		xorbs = append(xorbs, XorbEntry{Header: xh, Chunks: chunks})
	}
}

// FindFile returns the FileEntry for fileHash, or false if not present.
// Linear scan is fine here: a CAS server holds one Shard in memory per
// upload and looks files up by the handful of files in that upload, not
// across a large persisted shard index.
func (s *Shard) FindFile(fileHash merklehash.Hash) (FileEntry, bool) {
	for _, f := range s.Files {
		if f.Header.FileHash == fileHash {
			return f, true
		}
	}
	return FileEntry{}, false
}

// FindXorb returns the XorbEntry for xorbHash, or false if not present.
func (s *Shard) FindXorb(xorbHash merklehash.Hash) (XorbEntry, bool) {
	for _, x := range s.Xorbs {
		if x.Header.XorbHash == xorbHash {
			return x, true
		}
	}
	return XorbEntry{}, false
}

type countingWriter struct{ n uint64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += uint64(len(p))
	return len(p), nil
}
