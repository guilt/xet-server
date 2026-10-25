package lz4

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const frameMagic = 0x184D2204

// maxFrameOutput bounds DecompressFrame's total output when the caller has
// no more specific expected size. A chunk's declared UncompressedLength is
// 24-bit (at most ~16 MiB), so 64 MiB is generous for the only production
// caller while still preventing a frame made of many small, individually
// legal blocks from amplifying without bound.
const maxFrameOutput = 64 << 20

// DecompressFrame decompresses a complete LZ4 frame (magic number, frame
// descriptor, one or more blocks, end mark, optional checksums) per the
// public frame format spec. Checksums (header/block/content) are present
// on the wire but not verified here - this server only needs the decoded
// bytes to re-hash and compare against a client-claimed chunk hash, and a
// checksum mismatch would just mean the re-hash comparison fails anyway.
//
// Output is capped at maxFrameOutput. Callers that know the expected
// decoded size (the chunk decoder does: the chunk header's
// UncompressedLength) should use DecompressFrameLimit instead, which
// rejects the frame before it can allocate past that exact size.
func DecompressFrame(src []byte) ([]byte, error) {
	return DecompressFrameLimit(src, maxFrameOutput)
}

// DecompressFrameLimit is DecompressFrame with an explicit total-output
// ceiling. A frame whose blocks collectively decode past maxOutput is
// rejected with an error rather than allocating the extra bytes. This is
// the per-frame counterpart to decompressBlockUnknownSize's per-block
// ceiling: without it, a compressed frame containing many individually
// valid blocks could still amplify far beyond its input size.
func DecompressFrameLimit(src []byte, maxOutput int) ([]byte, error) {
	if maxOutput < 0 {
		return nil, fmt.Errorf("lz4: negative frame output limit %d", maxOutput)
	}
	if len(src) < 7 {
		return nil, fmt.Errorf("lz4: frame too short")
	}
	magic := binary.LittleEndian.Uint32(src[0:4])
	if magic != frameMagic {
		return nil, fmt.Errorf("lz4: bad frame magic %#x", magic)
	}
	pos := 4

	flg := src[pos]
	bd := src[pos+1]
	pos += 2

	version := flg >> 6
	if version != 1 {
		return nil, fmt.Errorf("lz4: unsupported frame version %d", version)
	}
	blockChecksumFlag := flg&(1<<4) != 0
	contentSizeFlag := flg&(1<<3) != 0
	contentChecksumFlag := flg&(1<<2) != 0
	dictIDFlag := flg&(1<<0) != 0

	blockMaxSizeCode := (bd >> 4) & 0x7

	if contentSizeFlag {
		pos += 8 // content size field, unused: block sizes are self-describing
	}
	if dictIDFlag {
		pos += 4
	}
	pos++ // header checksum byte

	if pos > len(src) {
		return nil, fmt.Errorf("lz4: frame truncated in header")
	}

	var out []byte
	for {
		if pos+4 > len(src) {
			return nil, fmt.Errorf("lz4: frame truncated reading block size")
		}
		blockSizeField := binary.LittleEndian.Uint32(src[pos : pos+4])
		pos += 4
		if blockSizeField == 0 {
			break // EndMark
		}

		uncompressedFlag := blockSizeField&(1<<31) != 0
		blockSize := int(blockSizeField &^ (1 << 31))

		if pos+blockSize > len(src) {
			return nil, fmt.Errorf("lz4: frame truncated in block data")
		}
		blockData := src[pos : pos+blockSize]
		pos += blockSize

		if blockChecksumFlag {
			pos += 4
		}

		if uncompressedFlag {
			if len(blockData) > maxOutput-len(out) {
				return nil, fmt.Errorf("lz4: frame output exceeds limit %d bytes", maxOutput)
			}
			out = append(out, blockData...)
			continue
		}

		maxBlockSize := maxBlockSizeForCode(blockMaxSizeCode)
		decoded, err := decompressBlockUnknownSize(blockData, maxBlockSize)
		if err != nil {
			return nil, fmt.Errorf("lz4: decompress block: %w", err)
		}
		if len(decoded) > maxOutput-len(out) {
			return nil, fmt.Errorf("lz4: frame output exceeds limit %d bytes", maxOutput)
		}
		out = append(out, decoded...)
	}

	if contentChecksumFlag {
		pos += 4
	}
	_ = pos

	return out, nil
}

// maxBlockSizeForCode maps the frame descriptor's 3-bit block-max-size code
// to a byte count, per the frame format spec (codes 4-7 only; 0-3 are
// reserved). This is not merely a sizing hint: per the frame format spec, a
// compliant encoder never produces a block whose *decompressed* size
// exceeds this value, so decompressBlockUnknownSize treats it as a hard
// ceiling - see its doc comment for why that matters.
func maxBlockSizeForCode(code byte) int {
	switch code {
	case 4:
		return 64 * 1024
	case 5:
		return 256 * 1024
	case 6:
		return 1024 * 1024
	case 7:
		return 4 * 1024 * 1024
	default:
		return 4 * 1024 * 1024 // permissive fallback for a reserved code; still bounded
	}
}

// decompressBlockUnknownSize decompresses one LZ4 block without knowing its
// exact decoded size in advance (the frame format, unlike some other LZ4
// containers, does not store per-block uncompressed size). Starts from a
// capacity hint and regrows if the block decodes larger - but only up to
// maxBlockSize, which is the frame descriptor's declared block-size-code
// ceiling, not just a starting guess.
//
// This ceiling is a real, exploitable amplification vector without it: LZ4
// block format allows a single ~4-byte match-length extension sequence to
// expand to hundreds of times its compressed size (a run of 0xFF extension
// bytes, each worth +255 to the match length - see readExtendedLength).
// Empirically, a ~16 MiB compressed chunk (comfortably inside a single
// chunk's 24-bit CompressedLength field, and far under casserver's 128 MiB
// whole-upload cap) decompressed to 3.8 GB and took ~8 seconds on ordinary
// hardware before this fix - and that cost is paid on every upload attempt
// of the same malicious xorb, since a chunk's hash can't be verified (and
// therefore deduplicated) without first decompressing it. A real,
// spec-compliant LZ4 encoder never produces a block exceeding the frame
// descriptor's declared max block size, so rejecting a block that grows
// past it is not a compatibility risk - it can only ever reject a
// malformed or hostile frame.
func decompressBlockUnknownSize(src []byte, maxBlockSize int) ([]byte, error) {
	dst := make([]byte, min(maxBlockSize, initialBlockSizeGuess))
	for {
		n, err := decompressBlockInto(src, dst)
		if err == nil {
			return dst[:n], nil
		}
		if errors.Is(err, ErrOutputTooSmall) {
			if len(dst) >= maxBlockSize {
				return nil, fmt.Errorf("lz4: block decompresses beyond the frame's declared max block size (%d bytes) - malformed or hostile frame", maxBlockSize)
			}
			dst = make([]byte, min(len(dst)*2, maxBlockSize))
			continue
		}
		return nil, err
	}
}

// initialBlockSizeGuess is the starting buffer size decompressBlockUnknownSize
// grows from, independent of maxBlockSize's ceiling - most real chunk
// payloads are far smaller than the frame's declared max block size, so
// starting small avoids a large upfront allocation for the (extremely
// common) case of a small chunk under a frame descriptor that declares a
// large max block size code.
const initialBlockSizeGuess = 8 * 1024
