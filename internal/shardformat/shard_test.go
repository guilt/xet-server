package shardformat

import (
	"bytes"
	"os"
	"testing"

	"github.com/guilt/xet-server/internal/merklehash"
)

func hashFromByte(b byte) merklehash.Hash {
	var buf [32]byte
	for i := range buf {
		buf[i] = b
	}
	h, _ := merklehash.FromRawBytes(buf[:])
	return h
}

func TestShard_RoundTrip(t *testing.T) {
	xorb1 := hashFromByte(0x11)
	xorb2 := hashFromByte(0x22)
	chunk1 := hashFromByte(0xA1)
	chunk2 := hashFromByte(0xA2)
	chunk3 := hashFromByte(0xA3)
	file1 := hashFromByte(0xF1)
	file2 := hashFromByte(0xF2)

	xorbs := []XorbEntry{
		{
			Header: XorbChunkSequenceHeader{XorbHash: xorb1, NumEntries: 2, NumBytesInXorb: 200},
			Chunks: []XorbChunkSequenceEntry{
				{ChunkHash: chunk1, ChunkByteRangeStart: 0, UnpackedSegmentBytes: 100},
				{ChunkHash: chunk2, ChunkByteRangeStart: 100, UnpackedSegmentBytes: 100},
			},
		},
		{
			Header: XorbChunkSequenceHeader{XorbHash: xorb2, NumEntries: 1, NumBytesInXorb: 50},
			Chunks: []XorbChunkSequenceEntry{
				{ChunkHash: chunk3, ChunkByteRangeStart: 0, UnpackedSegmentBytes: 50},
			},
		},
	}

	files := []FileEntry{
		{
			Header: FileDataSequenceHeader{FileHash: file1, NumEntries: 1},
			Entries: []FileDataSequenceEntry{
				{XorbHash: xorb1, UnpackedSegmentBytes: 200, ChunkIndexStart: 0, ChunkIndexEnd: 2},
			},
		},
		{
			Header: FileDataSequenceHeader{FileHash: file2, NumEntries: 2},
			Entries: []FileDataSequenceEntry{
				{XorbHash: xorb1, UnpackedSegmentBytes: 100, ChunkIndexStart: 0, ChunkIndexEnd: 1},
				{XorbHash: xorb2, UnpackedSegmentBytes: 50, ChunkIndexStart: 0, ChunkIndexEnd: 1},
			},
		},
	}

	var buf bytes.Buffer
	writtenFooter, err := WriteShard(&buf, files, xorbs)
	if err != nil {
		t.Fatalf("WriteShard() error = %v", err)
	}

	shard, err := ReadShard(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadShard() error = %v", err)
	}

	if shard.Footer.FileLookupNumEntry != writtenFooter.FileLookupNumEntry {
		t.Errorf("FileLookupNumEntry = %d, want %d", shard.Footer.FileLookupNumEntry, writtenFooter.FileLookupNumEntry)
	}
	if shard.Footer.XorbLookupNumEntry != writtenFooter.XorbLookupNumEntry {
		t.Errorf("XorbLookupNumEntry = %d, want %d", shard.Footer.XorbLookupNumEntry, writtenFooter.XorbLookupNumEntry)
	}
	if shard.Footer.ChunkLookupNumEntry != writtenFooter.ChunkLookupNumEntry {
		t.Errorf("ChunkLookupNumEntry = %d, want %d", shard.Footer.ChunkLookupNumEntry, writtenFooter.ChunkLookupNumEntry)
	}

	if len(shard.Files) != len(files) {
		t.Fatalf("parsed %d files, want %d", len(shard.Files), len(files))
	}
	f1, ok := shard.FindFile(file1)
	if !ok {
		t.Fatal("FindFile(file1) not found")
	}
	if len(f1.Entries) != 1 || f1.Entries[0].XorbHash != xorb1 || f1.Entries[0].ChunkIndexEnd != 2 {
		t.Errorf("file1 entries = %+v, want a single entry referencing xorb1 chunks [0,2)", f1.Entries)
	}

	f2, ok := shard.FindFile(file2)
	if !ok {
		t.Fatal("FindFile(file2) not found")
	}
	if len(f2.Entries) != 2 {
		t.Fatalf("file2 has %d entries, want 2", len(f2.Entries))
	}
	if f2.Entries[0].XorbHash != xorb1 || f2.Entries[1].XorbHash != xorb2 {
		t.Errorf("file2 entries reference wrong xorbs: %+v", f2.Entries)
	}

	if len(shard.Xorbs) != len(xorbs) {
		t.Fatalf("parsed %d xorbs, want %d", len(shard.Xorbs), len(xorbs))
	}
	x1, ok := shard.FindXorb(xorb1)
	if !ok {
		t.Fatal("FindXorb(xorb1) not found")
	}
	if len(x1.Chunks) != 2 || x1.Chunks[0].ChunkHash != chunk1 || x1.Chunks[1].ChunkHash != chunk2 {
		t.Errorf("xorb1 chunks = %+v, want [chunk1, chunk2]", x1.Chunks)
	}

	x2, ok := shard.FindXorb(xorb2)
	if !ok {
		t.Fatal("FindXorb(xorb2) not found")
	}
	if len(x2.Chunks) != 1 || x2.Chunks[0].ChunkHash != chunk3 {
		t.Errorf("xorb2 chunks = %+v, want [chunk3]", x2.Chunks)
	}
}

func TestShard_EmptyShard(t *testing.T) {
	var buf bytes.Buffer
	if _, err := WriteShard(&buf, nil, nil); err != nil {
		t.Fatalf("WriteShard() error = %v", err)
	}

	shard, err := ReadShard(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadShard() error = %v", err)
	}
	if len(shard.Files) != 0 || len(shard.Xorbs) != 0 {
		t.Errorf("empty shard parsed %d files, %d xorbs, want 0/0", len(shard.Files), len(shard.Xorbs))
	}
}

func TestHeader_RejectsBadTag(t *testing.T) {
	garbage := bytes.Repeat([]byte{0x00}, 48)
	if _, err := ReadHeader(bytes.NewReader(garbage)); err == nil {
		t.Error("ReadHeader() error = nil for garbage input, want error")
	}
}

func TestLookupByKey_FindsAllCollisions(t *testing.T) {
	entries := []FileLookupEntry{
		{Key: 1, Index: 0},
		{Key: 5, Index: 1},
		{Key: 5, Index: 2},
		{Key: 5, Index: 3},
		{Key: 9, Index: 4},
	}
	got := LookupByKey(entries, 5)
	if len(got) != 3 {
		t.Fatalf("LookupByKey(5) found %d entries, want 3", len(got))
	}
	for _, e := range got {
		if e.Key != 5 {
			t.Errorf("LookupByKey(5) returned entry with Key = %d", e.Key)
		}
	}
}

func TestLookupByKey_NoMatch(t *testing.T) {
	entries := []FileLookupEntry{{Key: 1, Index: 0}, {Key: 9, Index: 1}}
	if got := LookupByKey(entries, 5); len(got) != 0 {
		t.Errorf("LookupByKey(5) = %v, want empty", got)
	}
}

func TestFooterSize_ConstantMatchesActualWrite(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFooter(&buf, Footer{}); err != nil {
		t.Fatalf("WriteFooter() error = %v", err)
	}
	if buf.Len() != footerSize {
		t.Errorf("WriteFooter() wrote %d bytes, footerSize constant = %d", buf.Len(), footerSize)
	}
}

// TestReadShard_RealHFXetCapture parses an actual shard upload captured
// from a live hf_xet client session. This is what surfaced the bug this
// package's verification/metadata_ext support fixes: real clients always
// set MDB_FILE_FLAG_WITH_VERIFICATION and MDB_FILE_FLAG_WITH_METADATA_EXT,
// and a reader that ignores those flags misparses every byte after the
// first file header.
func TestReadShard_RealHFXetCapture(t *testing.T) {
	f, err := os.Open("testdata/real_upload_shard.bin")
	if err != nil {
		t.Fatalf("open testdata error = %v", err)
	}
	defer f.Close()

	shard, err := ReadShard(f)
	if err != nil {
		t.Fatalf("ReadShard() error = %v", err)
	}

	if len(shard.Files) != 1 {
		t.Fatalf("parsed %d files, want 1", len(shard.Files))
	}
	file := shard.Files[0]
	if !file.Header.ContainsVerification() {
		t.Error("real capture's file header does not have the verification flag set (test fixture assumption wrong?)")
	}
	if !file.Header.ContainsMetadataExt() {
		t.Error("real capture's file header does not have the metadata_ext flag set (test fixture assumption wrong?)")
	}
	if len(file.Verification) != len(file.Entries) {
		t.Errorf("got %d verification entries, want %d (one per FileDataSequenceEntry)", len(file.Verification), len(file.Entries))
	}
	if file.MetadataExt == nil {
		t.Fatal("MetadataExt = nil, want a parsed FileMetadataExt")
	}

	if len(file.Entries) != 1 {
		t.Fatalf("got %d FileDataSequenceEntry, want 1", len(file.Entries))
	}
	if file.Entries[0].UnpackedSegmentBytes != 500000 {
		t.Errorf("UnpackedSegmentBytes = %d, want 500000 (the uploaded file's actual size)", file.Entries[0].UnpackedSegmentBytes)
	}
	if file.Entries[0].ChunkIndexEnd != 9 {
		t.Errorf("ChunkIndexEnd = %d, want 9 (matches the paired real xorb capture's chunk count)", file.Entries[0].ChunkIndexEnd)
	}

	if len(shard.Xorbs) != 1 {
		t.Fatalf("parsed %d xorbs, want 1", len(shard.Xorbs))
	}
	if len(shard.Xorbs[0].Chunks) != 9 {
		t.Errorf("xorb has %d chunks, want 9", len(shard.Xorbs[0].Chunks))
	}
}

// TestWriteKeyedShardExpiring_KeyEveryChunkAndNothingElse pins the shape
// xet-core's export_as_keyed_shard produces: every chunk hash in both the
// xorb-info section and the chunk lookup table is DataHash::hmac(key), the
// key appears in the footer, and xorb/file identity is untouched.
func TestWriteKeyedShardExpiring_KeyEveryChunkAndNothingElse(t *testing.T) {
	xorb := hashFromByte(0x11)
	chunks := []merklehash.Hash{hashFromByte(0xA1), hashFromByte(0xA2)}
	key := hashFromByte(0x7E)
	xorbs := []XorbEntry{{
		Header: XorbChunkSequenceHeader{XorbHash: xorb, NumEntries: 2, NumBytesInXorb: 30},
		Chunks: []XorbChunkSequenceEntry{
			{ChunkHash: chunks[0], ChunkByteRangeStart: 0, UnpackedSegmentBytes: 10},
			{ChunkHash: chunks[1], ChunkByteRangeStart: 10, UnpackedSegmentBytes: 20},
		},
	}}

	var buf bytes.Buffer
	footer, err := WriteKeyedShardExpiring(&buf, xorbs, key, NoExpiry)
	if err != nil {
		t.Fatalf("WriteKeyedShardExpiring() error = %v", err)
	}
	if footer.ChunkHashHMACKey != key {
		t.Errorf("footer key = %s, want %s", footer.ChunkHashHMACKey.Hex(), key.Hex())
	}
	shard, err := ReadShard(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("ReadShard() error = %v", err)
	}
	if len(shard.Files) != 0 {
		t.Errorf("keyed shard has %d file entries, want none", len(shard.Files))
	}
	if shard.Footer.ChunkHashHMACKey != key || shard.Footer.ChunkLookupNumEntry != 2 {
		t.Fatalf("key=%s chunkLookup=%d, want key=%s and 2", shard.Footer.ChunkHashHMACKey.Hex(), shard.Footer.ChunkLookupNumEntry, key.Hex())
	}
	if len(shard.Xorbs) != 1 || shard.Xorbs[0].Header.XorbHash != xorb {
		t.Fatalf("xorb identity changed: %+v", shard.Xorbs)
	}
	for i, c := range shard.Xorbs[0].Chunks {
		if want := chunks[i].HMAC(key); c.ChunkHash != want {
			t.Errorf("chunk %d = %s, want keyed %s", i, c.ChunkHash.Hex()[:8], want.Hex()[:8])
		}
		if c.ChunkHash == chunks[i] {
			t.Errorf("chunk %d still carries its raw hash", i)
		}
	}

	if _, err := WriteKeyedShardExpiring(&buf, xorbs, merklehash.Hash{}, NoExpiry); err == nil {
		t.Error("writing with a zero key must fail")
	}
}
