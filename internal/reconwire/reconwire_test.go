package reconwire

// Tests for BuildV1/BuildV2's clipping and grouping logic, driven
// directly against fake FooterLookup/FetchURLBuilder callbacks - no HTTP
// server needed, since this package is a pure function of its inputs
// (see the package doc comment). internal/casserver's own integration
// tests exercise this same logic end-to-end through real HTTP requests;
// these tests pin the logic itself in isolation.

import (
	"errors"
	"testing"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/shardformat"
	"github.com/guilt/xet-server/internal/xorbformat"
)

func hashFromByte(b byte) merklehash.Hash {
	var buf [32]byte
	for i := range buf {
		buf[i] = b
	}
	h, _ := merklehash.FromRawBytes(buf[:])
	return h
}

func fakeFooterLookup(footers map[merklehash.Hash]xorbformat.FooterV1) FooterLookup {
	return func(hash merklehash.Hash) (xorbformat.FooterV1, bool) {
		f, ok := footers[hash]
		return f, ok
	}
}

func fakeFetchURLBuilder() (FetchURLBuilder, *int) {
	calls := 0
	return func(hash merklehash.Hash) (string, error) {
		calls++
		return "https://example.invalid/" + hash.Hex(), nil
	}, &calls
}

func TestBuildV1_WholeFileSingleXorb(t *testing.T) {
	xorbHash := hashFromByte(0x11)
	entries := []shardformat.FileDataSequenceEntry{
		{XorbHash: xorbHash, UnpackedSegmentBytes: 100, ChunkIndexStart: 0, ChunkIndexEnd: 2},
	}
	footers := map[merklehash.Hash]xorbformat.FooterV1{
		xorbHash: {ChunkBoundaryOffsets: []uint32{50, 110}},
	}
	fetchURL, calls := fakeFetchURLBuilder()

	resp, err := BuildV1(entries, 0, 99, fakeFooterLookup(footers), fetchURL)
	if err != nil {
		t.Fatalf("BuildV1() error = %v", err)
	}
	if len(resp.Terms) != 1 {
		t.Fatalf("got %d terms, want 1", len(resp.Terms))
	}
	if resp.Terms[0].Hash != xorbHash.Hex() {
		t.Errorf("term hash = %q, want %q", resp.Terms[0].Hash, xorbHash.Hex())
	}
	if resp.OffsetIntoFirstRange != 0 {
		t.Errorf("OffsetIntoFirstRange = %d, want 0", resp.OffsetIntoFirstRange)
	}
	entriesFor := resp.FetchInfo[xorbHash.Hex()]
	if len(entriesFor) != 1 {
		t.Fatalf("got %d fetch_info entries, want 1", len(entriesFor))
	}
	if entriesFor[0].URLRange != (ByteRange{Start: 0, End: 109}) {
		t.Errorf("URLRange = %+v, want {0 109}", entriesFor[0].URLRange)
	}
	if *calls != 1 {
		t.Errorf("fetchURL called %d times, want 1", *calls)
	}
}

func TestBuildV1_RangeSkipsTermsOutsideWindow(t *testing.T) {
	xorb1 := hashFromByte(0x11)
	xorb2 := hashFromByte(0x22)
	entries := []shardformat.FileDataSequenceEntry{
		{XorbHash: xorb1, UnpackedSegmentBytes: 100, ChunkIndexStart: 0, ChunkIndexEnd: 1},
		{XorbHash: xorb2, UnpackedSegmentBytes: 100, ChunkIndexStart: 0, ChunkIndexEnd: 1},
	}
	footers := map[merklehash.Hash]xorbformat.FooterV1{
		xorb1: {ChunkBoundaryOffsets: []uint32{100}},
		xorb2: {ChunkBoundaryOffsets: []uint32{100}},
	}
	fetchURL, _ := fakeFetchURLBuilder()

	// Range [150, 199] falls entirely within the second term (byte offset
	// 100-199) - the first term (0-99) must be skipped entirely.
	resp, err := BuildV1(entries, 150, 199, fakeFooterLookup(footers), fetchURL)
	if err != nil {
		t.Fatalf("BuildV1() error = %v", err)
	}
	if len(resp.Terms) != 1 {
		t.Fatalf("got %d terms, want 1 (first term outside window must be skipped)", len(resp.Terms))
	}
	if resp.Terms[0].Hash != xorb2.Hex() {
		t.Errorf("term hash = %q, want %q", resp.Terms[0].Hash, xorb2.Hex())
	}
	if resp.OffsetIntoFirstRange != 50 {
		t.Errorf("OffsetIntoFirstRange = %d, want 50 (150 - termStart 100)", resp.OffsetIntoFirstRange)
	}
}

func TestBuildV1_UnknownFooterReturnsError(t *testing.T) {
	xorbHash := hashFromByte(0x11)
	entries := []shardformat.FileDataSequenceEntry{
		{XorbHash: xorbHash, UnpackedSegmentBytes: 100, ChunkIndexStart: 0, ChunkIndexEnd: 1},
	}
	fetchURL, _ := fakeFetchURLBuilder()

	_, err := BuildV1(entries, 0, 99, fakeFooterLookup(nil), fetchURL)
	if err == nil {
		t.Fatal("expected an error for an unknown xorb footer, got nil")
	}
	var unknownFooter *ErrUnknownXorbFooter
	if !errors.As(err, &unknownFooter) {
		t.Errorf("error = %v, want *ErrUnknownXorbFooter", err)
	}
	if unknownFooter.Hash != xorbHash {
		t.Errorf("ErrUnknownXorbFooter.Hash = %s, want %s", unknownFooter.Hash.Hex(), xorbHash.Hex())
	}
}

func TestBuildV2_GroupsMultipleTermsUnderOneXorb(t *testing.T) {
	xorbHash := hashFromByte(0x11)
	entries := []shardformat.FileDataSequenceEntry{
		{XorbHash: xorbHash, UnpackedSegmentBytes: 50, ChunkIndexStart: 0, ChunkIndexEnd: 1},
		{XorbHash: xorbHash, UnpackedSegmentBytes: 50, ChunkIndexStart: 1, ChunkIndexEnd: 2},
	}
	footers := map[merklehash.Hash]xorbformat.FooterV1{
		xorbHash: {ChunkBoundaryOffsets: []uint32{50, 110}},
	}
	fetchURL, calls := fakeFetchURLBuilder()

	resp, err := BuildV2(entries, 0, 99, fakeFooterLookup(footers), fetchURL)
	if err != nil {
		t.Fatalf("BuildV2() error = %v", err)
	}
	fetches := resp.Xorbs[xorbHash.Hex()]
	if len(fetches) != 1 {
		t.Fatalf("got %d XorbMultiRangeFetch entries, want 1 (grouped under one URL)", len(fetches))
	}
	if len(fetches[0].Ranges) != 1 {
		t.Fatalf("got %d ranges, want 1 (adjacent 0-1 and 1-2 terms merge into 0-2)", len(fetches[0].Ranges))
	}
	if got := fetches[0].Ranges[0]; got.Chunks != (IndexRange{Start: 0, End: 2}) || got.Bytes != (ByteRange{Start: 0, End: 109}) {
		t.Errorf("merged range = %+v, want chunks 0-2 bytes 0-109", got)
	}
	// The URL builder must only be called once per distinct xorb hash,
	// even though two terms reference it - the whole point of V2's
	// grouping optimization.
	if *calls != 1 {
		t.Errorf("fetchURL called %d times, want 1 (reused across both terms)", *calls)
	}
}

func TestBuildV2_UnknownFooterReturnsError(t *testing.T) {
	xorbHash := hashFromByte(0x11)
	entries := []shardformat.FileDataSequenceEntry{
		{XorbHash: xorbHash, UnpackedSegmentBytes: 100, ChunkIndexStart: 0, ChunkIndexEnd: 1},
	}
	fetchURL, _ := fakeFetchURLBuilder()

	_, err := BuildV2(entries, 0, 99, fakeFooterLookup(nil), fetchURL)
	if err == nil {
		t.Fatal("expected an error for an unknown xorb footer, got nil")
	}
}

func TestFileSize_SumsUnpackedSegmentBytes(t *testing.T) {
	entries := []shardformat.FileDataSequenceEntry{
		{UnpackedSegmentBytes: 100},
		{UnpackedSegmentBytes: 250},
	}
	if got := FileSize(entries); got != 350 {
		t.Errorf("FileSize() = %d, want 350", got)
	}
}

// TestBuildV1_ChunkIndexOutOfRangeReturnsErrorNotPanic pins the fix for a
// real reachable crash: entries can originate from an untrusted upstream
// reconstruction response (internal/proxycas ingests one into
// casserver.Server.IngestFileRecon without re-deriving it - see the
// package doc comment), so a term whose ChunkIndexEnd exceeds its xorb's
// actual footer chunk count must be rejected with an error, never index
// footer.ChunkBoundaryOffsets out of bounds.
func TestBuildV1_ChunkIndexOutOfRangeReturnsErrorNotPanic(t *testing.T) {
	xorbHash := hashFromByte(0x11)
	entries := []shardformat.FileDataSequenceEntry{
		// The footer below has only 2 chunks (ChunkBoundaryOffsets has 2
		// entries), but this term claims chunk index 5 - a hostile or
		// malformed upstream response shape.
		{XorbHash: xorbHash, UnpackedSegmentBytes: 100, ChunkIndexStart: 0, ChunkIndexEnd: 5},
	}
	footers := map[merklehash.Hash]xorbformat.FooterV1{
		xorbHash: {ChunkBoundaryOffsets: []uint32{50, 100}},
	}
	fetchURL, _ := fakeFetchURLBuilder()

	_, err := BuildV1(entries, 0, 99, fakeFooterLookup(footers), fetchURL)
	if err == nil {
		t.Fatal("expected an error for an out-of-range chunk index, got nil")
	}
	var outOfRange *ErrChunkIndexOutOfRange
	if !errors.As(err, &outOfRange) {
		t.Errorf("error = %v, want *ErrChunkIndexOutOfRange", err)
	}
}

func TestBuildV2_ChunkIndexOutOfRangeReturnsErrorNotPanic(t *testing.T) {
	xorbHash := hashFromByte(0x11)
	entries := []shardformat.FileDataSequenceEntry{
		{XorbHash: xorbHash, UnpackedSegmentBytes: 100, ChunkIndexStart: 0, ChunkIndexEnd: 5},
	}
	footers := map[merklehash.Hash]xorbformat.FooterV1{
		xorbHash: {ChunkBoundaryOffsets: []uint32{50, 100}},
	}
	fetchURL, _ := fakeFetchURLBuilder()

	_, err := BuildV2(entries, 0, 99, fakeFooterLookup(footers), fetchURL)
	if err == nil {
		t.Fatal("expected an error for an out-of-range chunk index, got nil")
	}
	var outOfRange *ErrChunkIndexOutOfRange
	if !errors.As(err, &outOfRange) {
		t.Errorf("error = %v, want *ErrChunkIndexOutOfRange", err)
	}
}

// FuzzBuildV1_NeverPanics drives BuildV1 with adversarial
// FileDataSequenceEntry values - untrusted-shaped input by construction
// (see the package doc comment on why entries is not always internally
// consistent) - asserting only that it never panics, regardless of how
// the chunk-index fields relate to the footer's actual chunk count.
func FuzzBuildV1_NeverPanics(f *testing.F) {
	f.Add(uint32(0), uint32(1), uint32(2))
	f.Add(uint32(0), uint32(0), uint32(2))       // zero-width range
	f.Add(uint32(5), uint32(2), uint32(2))       // start > end
	f.Add(uint32(0), uint32(1000000), uint32(2)) // wildly out of range
	f.Add(uint32(0), uint32(0), uint32(0))       // empty footer

	f.Fuzz(func(t *testing.T, chunkIndexStart, chunkIndexEnd, footerChunkCount uint32) {
		if footerChunkCount > 10000 {
			footerChunkCount = footerChunkCount % 10000 // bound allocation
		}
		boundaryOffsets := make([]uint32, footerChunkCount)
		for i := range boundaryOffsets {
			boundaryOffsets[i] = uint32(i) * 10
		}
		xorbHash := hashFromByte(0x11)
		entries := []shardformat.FileDataSequenceEntry{
			{XorbHash: xorbHash, UnpackedSegmentBytes: 100, ChunkIndexStart: chunkIndexStart, ChunkIndexEnd: chunkIndexEnd},
		}
		footers := map[merklehash.Hash]xorbformat.FooterV1{
			xorbHash: {ChunkBoundaryOffsets: boundaryOffsets},
		}
		fetchURL, _ := fakeFetchURLBuilder()

		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("BuildV1 panicked on chunkIndexStart=%d chunkIndexEnd=%d footerChunkCount=%d: %v",
					chunkIndexStart, chunkIndexEnd, footerChunkCount, r)
			}
		}()
		BuildV1(entries, 0, 99, fakeFooterLookup(footers), fetchURL)
	})
}

// TestBuildV2_RangesAreSortedAndMerged pins the fix for a real dataset
// failure: a file with many terms against one shared xorb produced V1
// fetch_info entries in file order, so the grouped V2 range list was
// unsorted and contained duplicates/overlaps. xet-core then rejected the
// file with "chunk_start N not found in chunk_ranges ... for file term M".
func TestBuildV2_RangesAreSortedAndMerged(t *testing.T) {
	xorbHash := hashFromByte(0x12)
	// 200 chunks, 10 bytes each.
	offsets := make([]uint32, 200)
	for i := range offsets {
		offsets[i] = uint32((i + 1) * 10)
	}
	footers := map[merklehash.Hash]xorbformat.FooterV1{
		xorbHash: {ChunkBoundaryOffsets: offsets},
	}
	entries := []shardformat.FileDataSequenceEntry{
		{XorbHash: xorbHash, UnpackedSegmentBytes: 1140, ChunkIndexStart: 0, ChunkIndexEnd: 114},
		{XorbHash: xorbHash, UnpackedSegmentBytes: 10, ChunkIndexStart: 100, ChunkIndexEnd: 101},
		{XorbHash: xorbHash, UnpackedSegmentBytes: 10, ChunkIndexStart: 114, ChunkIndexEnd: 115},
		{XorbHash: xorbHash, UnpackedSegmentBytes: 10, ChunkIndexStart: 116, ChunkIndexEnd: 117},
		{XorbHash: xorbHash, UnpackedSegmentBytes: 10, ChunkIndexStart: 114, ChunkIndexEnd: 115},
		{XorbHash: xorbHash, UnpackedSegmentBytes: 10, ChunkIndexStart: 118, ChunkIndexEnd: 119},
		{XorbHash: xorbHash, UnpackedSegmentBytes: 10, ChunkIndexStart: 119, ChunkIndexEnd: 120},
	}
	fetchURL, _ := fakeFetchURLBuilder()

	resp, err := BuildV2(entries, 0, int64(1<<20), fakeFooterLookup(footers), fetchURL)
	if err != nil {
		t.Fatalf("BuildV2() error = %v", err)
	}
	fetches := resp.Xorbs[xorbHash.Hex()]
	if len(fetches) != 1 {
		t.Fatalf("got %d fetches, want 1", len(fetches))
	}
	want := []XorbRangeDescriptor{
		{Chunks: IndexRange{Start: 0, End: 115}, Bytes: ByteRange{Start: 0, End: 1149}},
		{Chunks: IndexRange{Start: 116, End: 117}, Bytes: ByteRange{Start: 1160, End: 1169}},
		{Chunks: IndexRange{Start: 118, End: 120}, Bytes: ByteRange{Start: 1180, End: 1199}},
	}
	if len(fetches[0].Ranges) != len(want) {
		t.Fatalf("got ranges %+v, want %+v", fetches[0].Ranges, want)
	}
	for i := range want {
		if fetches[0].Ranges[i] != want[i] {
			t.Errorf("range[%d] = %+v, want %+v", i, fetches[0].Ranges[i], want[i])
		}
	}
	for i, term := range resp.Terms {
		found := false
		for _, r := range fetches[0].Ranges {
			if term.Range.Start >= r.Chunks.Start && term.Range.Start < r.Chunks.End {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("term[%d] chunk_start %d is not covered by any merged range", i, term.Range.Start)
		}
	}
}
