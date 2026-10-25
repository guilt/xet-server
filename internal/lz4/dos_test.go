package lz4

// Regression test for a real, confirmed decompression-amplification DoS
// found while investigating whether the dedup fast-path could be starved
// or bypassed cheaply. LZ4's block format lets a single match-length
// extension sequence (a run of 0xFF bytes, each worth +255 to the match
// length - see readExtendedLength) expand to hundreds of times its
// compressed size. decompressBlockUnknownSize previously regrew its
// output buffer by doubling with no ceiling every time decompression
// exceeded the current buffer - so a ~16 MiB compressed chunk (well
// within a single chunk's 24-bit CompressedLength field, and far under
// casserver's 128 MiB whole-upload cap) decompressed to 3.8 GB and took
// ~8 seconds on ordinary hardware before this fix. Critically, this cost
// is paid on *every* upload attempt of the same malicious xorb, since a
// chunk's hash can't be verified (and therefore deduplicated) without
// first decompressing it - dedup provides no mitigation for this attack
// shape, unlike a repeated identical valid upload.
//
// The fix treats the frame descriptor's declared max-block-size code as a
// hard ceiling (a real, spec-compliant encoder never produces a block
// exceeding it), not merely an initial sizing guess. DecompressFrameLimit
// additionally caps total frame output, because many individually legal
// blocks could otherwise still amplify without bound.

import (
	"encoding/binary"
	"runtime"
	"testing"
	"time"
)

// buildAmplificationBombBlock constructs a minimal LZ4 block: one literal
// byte, then a match (offset=1, so it repeats that single byte) whose
// length is inflated via n extended-length bytes (each worth +255), then a
// trivial empty terminating literal sequence.
func buildAmplificationBombBlock(n int) []byte {
	var b []byte
	b = append(b, 0x1F)       // token: litLen=1, matchLen nibble=15 (extension follows)
	b = append(b, 'A')        // the one literal byte
	b = append(b, 0x01, 0x00) // offset = 1, little-endian
	for i := 0; i < n; i++ {
		b = append(b, 0xFF) // each contributes +255 to the match length
	}
	b = append(b, 0x01) // terminating extension byte (< 255): +1, stop extending
	b = append(b, 0x00) // final literal-only sequence (litLen=0): ends the block
	return b
}

func buildAmplificationBombFrame(blockData []byte) []byte {
	var buf []byte
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], frameMagic)
	buf = append(buf, tmp[:]...)
	buf = append(buf, 0x40, 0x70, 0x00)                           // FLG (version 1, no optional fields), BD (block max size code 7), header checksum
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(blockData))) // compressed block, no uncompressed-flag bit
	buf = append(buf, tmp[:]...)
	buf = append(buf, blockData...)
	binary.LittleEndian.PutUint32(tmp[:], 0) // EndMark
	buf = append(buf, tmp[:]...)
	return buf
}

func TestDecompressFrame_RejectsAmplificationBomb(t *testing.T) {
	// ~1 MiB of extension bytes claims ~255 MiB of output: still far
	// beyond the frame's 4 MiB declared ceiling, but small enough that the
	// rejection path stays fast under -race and on a loaded CI machine.
	// (The original 16 MiB payload decompressed to 3.8 GB pre-fix; 1 MiB
	// already exceeds the ceiling by ~60x and catches the same regression.)
	block := buildAmplificationBombBlock(1_000_000)
	frame := buildAmplificationBombFrame(block)
	t.Logf("bomb frame is %d bytes", len(frame))

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)

	done := make(chan struct{})
	var decodeErr error
	go func() {
		defer close(done)
		_, decodeErr = DecompressFrame(frame)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("DecompressFrame() did not return within 30s on an amplification-bomb frame - looks like the ceiling regressed")
	}

	if decodeErr == nil {
		t.Fatal("DecompressFrame() error = nil, want a rejection - a block claiming to decompress far beyond the frame's declared max block size must be rejected, not honored")
	}
	t.Logf("correctly rejected: %v", decodeErr)

	runtime.ReadMemStats(&after)
	// The frame descriptor here declares block-size code 7 (4 MiB max), so
	// a correct implementation allocates at most a few MiB working through
	// the ceiling before giving up - nowhere near the ~750 MB+ this
	// exact payload caused pre-fix.
	const maxReasonableGrowth = 64 * 1024 * 1024
	grew := after.TotalAlloc - before.TotalAlloc
	if grew > maxReasonableGrowth {
		t.Errorf("heap grew by %d bytes rejecting a bomb frame, want < %d - looks like the max-block-size ceiling isn't being enforced", grew, maxReasonableGrowth)
	}
}

func buildMultiBlockFrame(blocks [][]byte) []byte {
	var buf []byte
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], frameMagic)
	buf = append(buf, tmp[:]...)
	buf = append(buf, 0x40, 0x70, 0x00) // FLG, BD (code 7), header checksum
	for _, block := range blocks {
		binary.LittleEndian.PutUint32(tmp[:], uint32(len(block)))
		buf = append(buf, tmp[:]...)
		buf = append(buf, block...)
	}
	binary.LittleEndian.PutUint32(tmp[:], 0) // EndMark
	buf = append(buf, tmp[:]...)
	return buf
}

// TestDecompressFrameLimit_RejectsMultiBlockAmplification pins the
// per-frame total-output ceiling. Each individual block here decodes to
// ~3 MiB, under the frame's 4 MiB block ceiling, but three of them exceed
// the 8 MiB limit passed by the caller. Without a total cap the decoder
// would happily allocate all three (and a hostile frame could contain
// hundreds).
func TestDecompressFrameLimit_RejectsMultiBlockAmplification(t *testing.T) {
	block := buildAmplificationBombBlock(12_000) // ~3.06 MiB claimed output
	frame := buildMultiBlockFrame([][]byte{block, block, block})

	if _, err := DecompressFrameLimit(frame, 8*1024*1024); err == nil {
		t.Fatal("DecompressFrameLimit() error = nil, want rejection after the frame exceeds its total output limit")
	}
}

func TestDecompressFrame_LargeBlockUnderCeilingStillWorks(t *testing.T) {
	// A legitimate, non-malicious decompression that's simply large (not
	// an amplification attack - ~1:1 compressed:decompressed ratio) must
	// still succeed as long as it's within the frame's declared max block
	// size. Built as an all-literal block (no back-references), which
	// exercises decompressBlockUnknownSize's growth-toward-the-ceiling
	// path the same way a real compressed block would, just without an
	// amplifying match.
	const decodedSize = 3 * 1024 * 1024 // under the 4 MiB code-7 ceiling
	data := make([]byte, decodedSize)
	for i := range data {
		data[i] = byte(i % 251) // varied, so it can't be mistaken for the uncompressed-block path's data
	}
	block := buildAllLiteralBlock(data)
	frame := buildAmplificationBombFrame(block) // same frame wrapper; just a differently-shaped block payload

	out, err := DecompressFrame(frame)
	if err != nil {
		t.Fatalf("DecompressFrame() error = %v, want a legitimate large block to still decode", err)
	}
	if len(out) != len(data) {
		t.Fatalf("decoded %d bytes, want %d", len(out), len(data))
	}
	for i := range data {
		if out[i] != data[i] {
			t.Fatalf("decoded byte %d = %d, want %d", i, out[i], data[i])
		}
	}
}

// buildAllLiteralBlock encodes data as a single LZ4 block sequence of pure
// literals (no back-reference match), using the token's literal-length
// extension for lengths >= 15.
func buildAllLiteralBlock(data []byte) []byte {
	var b []byte
	litLen := len(data)
	if litLen < 15 {
		b = append(b, byte(litLen<<4))
	} else {
		b = append(b, 0xF0)
		remaining := litLen - 15
		for remaining >= 255 {
			b = append(b, 0xFF)
			remaining -= 255
		}
		b = append(b, byte(remaining))
	}
	b = append(b, data...)
	// Per the block format's parsing restrictions, a block may end here
	// (literals-only, no trailing match) - decompressBlockInto's own
	// "si == len(src)" check handles this.
	return b
}
