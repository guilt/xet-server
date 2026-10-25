// Package xorbformat implements the on-wire binary layout of a xorb - the
// aggregated-chunk storage unit real Xet clients (hf_xet/xet-core) upload
// via POST /v1/xorbs/{prefix}/{hash} - ported from
// xet_core_structures/src/xorb_object/{xorb_chunk_format,xorb_object_format}.rs.
//
// A CAS server's job is to store a xorb's serialized bytes as an opaque
// blob and later hand back raw byte ranges for reconstruction; the
// (possibly compressed) chunk payloads are never decompressed
// server-side - only the client does that after fetching. Accordingly,
// this package parses chunk headers and the V1 footer (hashes, boundary
// offsets) without needing to implement any compression codec.
package xorbformat

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/guilt/xet-server/internal/bg4"
	"github.com/guilt/xet-server/internal/lz4"
	"github.com/guilt/xet-server/internal/merklehash"
)

// CompressionScheme mirrors xet_core_structures::CompressionScheme's wire
// discriminants (compression_scheme.rs). Never decoded/encoded here beyond
// recording which scheme a chunk claims - the server treats chunk payload
// bytes as opaque regardless of scheme.
type CompressionScheme uint8

const (
	CompressionNone             CompressionScheme = 0
	CompressionLZ4              CompressionScheme = 1
	CompressionByteGrouping4LZ4 CompressionScheme = 2
	CompressionAuto             CompressionScheme = 99 // never valid on the wire
)

// ChunkHeaderSize is the fixed 8-byte size of a XorbChunkHeader:
// version(1) + compressed_length(3) + compression_scheme(1) + uncompressed_length(3).
const ChunkHeaderSize = 8

// ChunkHeader mirrors xorb_chunk_format.rs's XorbChunkHeader.
type ChunkHeader struct {
	Version            uint8
	CompressedLength   uint32 // 24-bit on the wire
	CompressionScheme  CompressionScheme
	UncompressedLength uint32 // 24-bit on the wire
}

// ReadChunkHeader reads and validates one 8-byte chunk header from r.
func ReadChunkHeader(r io.Reader) (ChunkHeader, error) {
	var buf [ChunkHeaderSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return ChunkHeader{}, err
	}
	return parseChunkHeader(buf)
}

func parseChunkHeader(buf [ChunkHeaderSize]byte) (ChunkHeader, error) {
	h := ChunkHeader{
		Version:            buf[0],
		CompressedLength:   read24LE(buf[1:4]),
		CompressionScheme:  CompressionScheme(buf[4]),
		UncompressedLength: read24LE(buf[5:8]),
	}
	if h.Version != 0 {
		return ChunkHeader{}, fmt.Errorf("xorbformat: chunk header version %d too high, want 0", h.Version)
	}
	switch h.CompressionScheme {
	case CompressionNone, CompressionLZ4, CompressionByteGrouping4LZ4:
	default:
		return ChunkHeader{}, fmt.Errorf("xorbformat: invalid compression scheme %d", h.CompressionScheme)
	}
	return h, nil
}

// WriteChunkHeader writes h's 8-byte wire representation to w.
func WriteChunkHeader(w io.Writer, h ChunkHeader) error {
	var buf [ChunkHeaderSize]byte
	buf[0] = h.Version
	write24LE(buf[1:4], h.CompressedLength)
	buf[4] = byte(h.CompressionScheme)
	write24LE(buf[5:8], h.UncompressedLength)
	_, err := w.Write(buf[:])
	return err
}

func read24LE(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

func write24LE(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
}

// ChunkEntry describes one chunk as found while scanning a xorb's chunk
// section: its header plus the physical byte offset (from the start of the
// xorb) where its header begins.
type ChunkEntry struct {
	Header       ChunkHeader
	HeaderOffset int64
	DataOffset   int64 // HeaderOffset + ChunkHeaderSize
}

// DecompressChunkPayload returns the uncompressed bytes of one chunk's
// payload per its declared compression scheme. Real hf_xet clients upload
// xorbs without a footer (chunk metadata is reconstructed by the server
// from the raw chunk stream - see casserver.IngestXorb), so this is
// the only way to obtain a chunk's true content and independently verify
// its claimed hash. Exported (rather than kept package-internal to
// casserver) since it's a pure codec-dispatch function with no
// casserver-specific state - a natural fit for this package alongside
// the rest of the wire-format logic it already owns.
func DecompressChunkPayload(scheme CompressionScheme, payload []byte, uncompressedLen uint32) ([]byte, error) {
	switch scheme {
	case CompressionNone:
		if uint32(len(payload)) != uncompressedLen {
			return nil, fmt.Errorf("uncompressed chunk length %d does not match header's uncompressed_length %d", len(payload), uncompressedLen)
		}
		return payload, nil
	case CompressionLZ4:
		decoded, err := lz4.DecompressFrameLimit(payload, int(uncompressedLen))
		if err != nil {
			return nil, err
		}
		if uint32(len(decoded)) != uncompressedLen {
			return nil, fmt.Errorf("LZ4-decoded chunk length %d does not match header's uncompressed_length %d", len(decoded), uncompressedLen)
		}
		return decoded, nil
	case CompressionByteGrouping4LZ4:
		decoded, err := lz4.DecompressFrameLimit(payload, int(uncompressedLen))
		if err != nil {
			return nil, err
		}
		ungrouped := bg4.Reverse(decoded)
		if uint32(len(ungrouped)) != uncompressedLen {
			return nil, fmt.Errorf("BG4+LZ4-decoded chunk length %d does not match header's uncompressed_length %d", len(ungrouped), uncompressedLen)
		}
		return ungrouped, nil
	default:
		return nil, fmt.Errorf("unsupported compression scheme %d", scheme)
	}
}

// ScanChunks reads consecutive chunk headers from r (which must be
// positioned at the start of the chunk section), skipping over each
// chunk's compressed payload via Seek, until it encounters the xorb
// footer's ident ("XETBLOB") or EOF. Returns the chunk entries found.
//
// r must also implement io.Seeker; ScanChunks does not decompress or
// otherwise inspect payload bytes.
func ScanChunks(r io.ReadSeeker) ([]ChunkEntry, error) {
	var entries []ChunkEntry
	offset, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}

	for {
		var peek [len(xorbIdent)]byte
		n, err := io.ReadFull(r, peek[:])
		if err == io.EOF || (err == io.ErrUnexpectedEOF && n == 0) {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		if peek == xorbIdent {
			break
		}
		// Not the footer ident: rewind to offset and read a full chunk header.
		if _, err := r.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
		header, err := ReadChunkHeader(r)
		if err != nil {
			return nil, err
		}
		entries = append(entries, ChunkEntry{
			Header:       header,
			HeaderOffset: offset,
			DataOffset:   offset + ChunkHeaderSize,
		})
		next := offset + ChunkHeaderSize + int64(header.CompressedLength)
		if _, err := r.Seek(next, io.SeekStart); err != nil {
			return nil, err
		}
		offset = next
	}
	return entries, nil
}

// DeriveFooter independently reconstructs a xorb's V1 footer and content
// hash by scanning r's chunk headers (via ScanChunks) and decompressing
// each chunk's payload (via DecompressChunkPayload) - the same
// reconstruction real hf_xet clients rely on the server side to perform,
// since a real upload never includes a footer at all ("XORBs are sent
// without footer - the server/client reconstructs it from chunk data",
// per xet-core's file_upload_session.rs).
//
// Used by casserver.IngestXorb to independently verify a freshly
// -uploaded xorb's claimed hash against its actual chunk contents.
//
// r must implement io.ReaderAt in addition to io.ReadSeeker, to read each
// chunk's payload independently of ScanChunks' own sequential Seek
// position.
func DeriveFooter(r interface {
	io.ReadSeeker
	io.ReaderAt
}) (footer FooterV1, computedHash merklehash.Hash, err error) {
	entries, err := ScanChunks(r)
	if err != nil {
		return FooterV1{}, merklehash.Hash{}, err
	}
	if len(entries) == 0 {
		return FooterV1{}, merklehash.Hash{}, fmt.Errorf("no chunks found")
	}

	var chunkHashes []merklehash.Hash
	var chunkEntries []merklehash.ChunkEntry
	var boundaryOffsets, unpackedOffsets []uint32
	for i, e := range entries {
		payload := make([]byte, e.Header.CompressedLength)
		if _, err := r.ReadAt(payload, e.DataOffset); err != nil {
			return FooterV1{}, merklehash.Hash{}, fmt.Errorf("chunk %d: read payload: %w", i, err)
		}
		decoded, err := DecompressChunkPayload(e.Header.CompressionScheme, payload, e.Header.UncompressedLength)
		if err != nil {
			return FooterV1{}, merklehash.Hash{}, fmt.Errorf("chunk %d: %w", i, err)
		}
		h := merklehash.ComputeDataHash(decoded)
		chunkHashes = append(chunkHashes, h)
		chunkEntries = append(chunkEntries, merklehash.ChunkEntry{Hash: h, Size: uint64(len(decoded))})
		boundaryOffsets = append(boundaryOffsets, uint32(e.DataOffset+int64(e.Header.CompressedLength)))
		var unpacked uint32
		if len(unpackedOffsets) > 0 {
			unpacked = unpackedOffsets[len(unpackedOffsets)-1]
		}
		unpackedOffsets = append(unpackedOffsets, unpacked+e.Header.UncompressedLength)
	}

	computedHash = merklehash.XorbHash(chunkEntries)
	footer = FooterV1{
		XorbHash:             computedHash,
		ChunkHashes:          chunkHashes,
		ChunkBoundaryOffsets: boundaryOffsets,
		UnpackedChunkOffsets: unpackedOffsets,
		NumChunks:            uint32(len(entries)),
	}
	return footer, computedHash, nil
}

var xorbIdent = [7]byte{'X', 'E', 'T', 'B', 'L', 'O', 'B'}
var hashIdent = [7]byte{'X', 'B', 'L', 'B', 'H', 'S', 'H'}
var boundaryIdent = [7]byte{'X', 'B', 'L', 'B', 'B', 'N', 'D'}

const (
	footerVersionV1    = 1
	hashSectionVersion = 0
	boundarySectionVer = 1
	nonceBufferLen     = 16

	// maxFooterEntryPreallocate caps upfront allocation capacity for the
	// footer's per-chunk slices: numChunks is an attacker-controlled
	// uint32 wire field, and even though ParseFooterV1 isn't reachable
	// from any current HTTP request path (real clients upload xorbs
	// without a footer - see PROTOCOL.md #2), it still parses
	// untrusted-shaped data and should not let a tiny malicious footer
	// force a multi-gigabyte allocation before validating any of the
	// claimed entries actually exist on the wire.
	maxFooterEntryPreallocate = 4096
)

// FooterV1 mirrors xet_object_format.rs's XorbObjectInfoV1: the trailer
// written after a xorb's chunk section, carrying the xorb's content hash,
// per-chunk hashes, and both physical (compressed) and logical
// (uncompressed) chunk boundary offsets.
type FooterV1 struct {
	XorbHash             merklehash.Hash
	ChunkHashes          []merklehash.Hash
	ChunkBoundaryOffsets []uint32 // physical (compressed+header) byte offsets, one per chunk
	UnpackedChunkOffsets []uint32 // logical (uncompressed) byte offsets, one per chunk
	NumChunks            uint32
}

// ParseFooterV1 reads a V1 footer from r, which must be positioned at the
// start of the footer (immediately after the last chunk's payload bytes).
func ParseFooterV1(r io.Reader) (FooterV1, error) {
	var f FooterV1

	ident, err := readIdent(r)
	if err != nil {
		return f, err
	}
	if ident != xorbIdent {
		return f, fmt.Errorf("xorbformat: invalid footer ident %q, want XETBLOB", ident)
	}
	version, err := readU8(r)
	if err != nil {
		return f, err
	}
	if version != footerVersionV1 {
		return f, fmt.Errorf("xorbformat: unsupported footer version %d, want %d", version, footerVersionV1)
	}
	xorbHashBytes, err := readN(r, 32)
	if err != nil {
		return f, err
	}
	f.XorbHash, err = merklehash.FromRawBytes(xorbHashBytes)
	if err != nil {
		return f, err
	}

	// Hash section.
	hashIdentGot, err := readIdent(r)
	if err != nil {
		return f, err
	}
	if hashIdentGot != hashIdent {
		return f, fmt.Errorf("xorbformat: invalid hash section ident %q, want XBLBHSH", hashIdentGot)
	}
	hashesVersion, err := readU8(r)
	if err != nil {
		return f, err
	}
	if hashesVersion != hashSectionVersion {
		return f, fmt.Errorf("xorbformat: unsupported hash section version %d", hashesVersion)
	}
	numChunks, err := readU32(r)
	if err != nil {
		return f, err
	}
	f.ChunkHashes = make([]merklehash.Hash, 0, min(uint64(numChunks), maxFooterEntryPreallocate))
	for i := uint32(0); i < numChunks; i++ {
		b, err := readN(r, 32)
		if err != nil {
			return f, err
		}
		h, err := merklehash.FromRawBytes(b)
		if err != nil {
			return f, err
		}
		f.ChunkHashes = append(f.ChunkHashes, h)
	}

	// Boundary section.
	boundaryIdentGot, err := readIdent(r)
	if err != nil {
		return f, err
	}
	if boundaryIdentGot != boundaryIdent {
		return f, fmt.Errorf("xorbformat: invalid boundary section ident %q, want XBLBBND", boundaryIdentGot)
	}
	boundariesVersion, err := readU8(r)
	if err != nil {
		return f, err
	}
	if boundariesVersion != boundarySectionVer {
		return f, fmt.Errorf("xorbformat: unsupported boundary section version %d", boundariesVersion)
	}
	numChunks2, err := readU32(r)
	if err != nil {
		return f, err
	}
	if numChunks2 != numChunks {
		return f, fmt.Errorf("xorbformat: inconsistent num_chunks between hash (%d) and boundary (%d) sections", numChunks, numChunks2)
	}

	f.ChunkBoundaryOffsets = make([]uint32, 0, min(uint64(numChunks), maxFooterEntryPreallocate))
	for i := uint32(0); i < numChunks; i++ {
		v, err := readU32(r)
		if err != nil {
			return f, err
		}
		f.ChunkBoundaryOffsets = append(f.ChunkBoundaryOffsets, v)
	}
	f.UnpackedChunkOffsets = make([]uint32, 0, min(uint64(numChunks), maxFooterEntryPreallocate))
	for i := uint32(0); i < numChunks; i++ {
		v, err := readU32(r)
		if err != nil {
			return f, err
		}
		f.UnpackedChunkOffsets = append(f.UnpackedChunkOffsets, v)
	}

	// Fixed tail.
	numChunks3, err := readU32(r)
	if err != nil {
		return f, err
	}
	if numChunks3 != numChunks {
		return f, fmt.Errorf("xorbformat: inconsistent num_chunks in footer tail (%d vs %d)", numChunks3, numChunks)
	}
	f.NumChunks = numChunks

	if _, err := readU32(r); err != nil { // hashes_section_offset_from_end
		return f, err
	}
	if _, err := readU32(r); err != nil { // boundary_section_offset_from_end
		return f, err
	}
	if _, err := readN(r, nonceBufferLen); err != nil {
		return f, err
	}

	return f, nil
}

func readIdent(r io.Reader) ([7]byte, error) {
	var b [7]byte
	_, err := io.ReadFull(r, b[:])
	return b, err
}

func readU8(r io.Reader) (uint8, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return b[0], nil
}

func readU32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func readN(r io.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}
