# `github.com/guilt/xet-server/internal/lz4`

```
package lz4 // import "github.com/guilt/xet-server/internal/lz4"

Package lz4 implements LZ4 block and frame decompression from the public LZ4
format specifications:
  - Block format: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md
  - Frame format: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md

Written from these specifications rather than ported from any existing
implementation. xet-core (via the Rust lz4_flex crate's "frame" module) always
uses the LZ4 *frame* format on the wire, never raw blocks - so a CAS server
that wants to independently verify chunk hashes for LZ4-compressed chunks
needs a frame-aware decoder, not just a block decoder. Only decompression is
implemented; this server never needs to produce LZ4 output itself.

VARIABLES

var ErrOutputTooSmall = errors.New("lz4: output buffer too small")
    ErrOutputTooSmall is returned by decompressBlockInto when dst is not large
    enough to hold the decoded block. Callers that don't know the decoded size
    in advance (the LZ4 frame format doesn't store it) can retry with a larger
    buffer.


FUNCTIONS

func DecompressBlock(src []byte, dstLen int) ([]byte, error)
    DecompressBlock decompresses a single LZ4 block (no frame header) per the
    block format spec, into a buffer of exactly dstLen bytes.

func DecompressFrame(src []byte) ([]byte, error)
    DecompressFrame decompresses a complete LZ4 frame (magic number, frame
    descriptor, one or more blocks, end mark, optional checksums) per the public
    frame format spec. Checksums (header/block/content) are present on the wire
    but not verified here - this server only needs the decoded bytes to re-hash
    and compare against a client-claimed chunk hash, and a checksum mismatch
    would just mean the re-hash comparison fails anyway.

    Output is capped at maxFrameOutput. Callers that know the expected decoded
    size (the chunk decoder does: the chunk header's UncompressedLength) should
    use DecompressFrameLimit instead, which rejects the frame before it can
    allocate past that exact size.

func DecompressFrameLimit(src []byte, maxOutput int) ([]byte, error)
    DecompressFrameLimit is DecompressFrame with an explicit total-output
    ceiling. A frame whose blocks collectively decode past maxOutput is rejected
    with an error rather than allocating the extra bytes. This is the per-frame
    counterpart to decompressBlockUnknownSize's per-block ceiling: without it,
    a compressed frame containing many individually valid blocks could still
    amplify far beyond its input size.
```
