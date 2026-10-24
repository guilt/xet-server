package proxycas

// partial_xorb_test.go pins the behavior around reconstructions whose
// fetch_info cites only PART of a xorb - the common real-world shape,
// since a xorb packs chunks from many files and each file's
// reconstruction cites only the chunk ranges that file needs.
//
// The bytes behind such a citation cannot reproduce the original xorb's
// hash, and the presigned URL is signature-scoped to exactly the cited
// range (asking for the whole object returns 403), so there is no way to
// widen it. The proxy instead caches the exact slice as a new xorb under
// its own content hash and rewrites the file term to reference it, which
// keeps the file offline-capable. If fetch_info does not exactly cover a
// term, the client still downloads via a live relay rather than failing.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/reconwire"
	"github.com/guilt/xet-server/internal/xorbformat"
)

func TestCitesXorbFromStart(t *testing.T) {
	cases := []struct {
		name  string
		infos []reconwire.FetchInfoEntry
		want  bool
	}{
		{
			name:  "whole xorb cited from chunk 0",
			infos: []reconwire.FetchInfoEntry{{Range: reconwire.IndexRange{Start: 0, End: 1047}}},
			want:  true,
		},
		{
			name:  "mid-xorb slice (real shape: file used chunks 15-21 of a shared xorb)",
			infos: []reconwire.FetchInfoEntry{{Range: reconwire.IndexRange{Start: 15, End: 21}}},
			want:  false,
		},
		{
			name: "multiple entries, one starting at 0",
			infos: []reconwire.FetchInfoEntry{
				{Range: reconwire.IndexRange{Start: 40, End: 60}},
				{Range: reconwire.IndexRange{Start: 0, End: 39}},
			},
			want: true,
		},
		{
			name: "multiple entries, none starting at 0",
			infos: []reconwire.FetchInfoEntry{
				{Range: reconwire.IndexRange{Start: 40, End: 60}},
				{Range: reconwire.IndexRange{Start: 61, End: 90}},
			},
			want: false,
		},
		{
			name:  "no entries",
			infos: nil,
			want:  false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := citesXorbFromStart(tc.infos); got != tc.want {
				t.Errorf("citesXorbFromStart() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestReconstruction_PartialXorbSliceIsCachedAsSyntheticXorb pins the
// dataset fix: when a file cites only one chunk range of a shared xorb,
// the proxy fetches exactly that slice, stores it as a complete xorb of
// its own, and rewrites the file's reconstruction to reference it. The
// file is then fully servable with upstream offline, instead of always
// being relayed live and leaving nothing behind for the xetd handoff.
func TestReconstruction_PartialXorbSliceIsCachedAsSyntheticXorb(t *testing.T) {
	payloads := [][]byte{[]byte("first chunk"), []byte("second chunk")}
	blob, xorbHash := buildFooterlessXorb(t, payloads)
	entries, err := xorbformat.ScanChunks(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("ScanChunks() error = %v", err)
	}
	firstChunkEnd := entries[0].DataOffset + int64(entries[0].Header.CompressedLength) - 1
	_, syntheticHash := buildFooterlessXorb(t, payloads[:1])
	fileHash := hashFromByte(0xE4)

	cdn, ranges := cdnRangeServer(blob)
	defer cdn.Close()

	upstream := newRecoUpstream(fileHash.Hex())
	upstream.resp = &reconwire.ResponseV1{
		Terms: []reconwire.Term{
			{Hash: xorbHash.Hex(), Range: reconwire.IndexRange{Start: 0, End: 1}, UnpackedLength: uint32(len(payloads[0]))},
		},
		FetchInfo: map[string][]reconwire.FetchInfoEntry{
			xorbHash.Hex(): {
				{URL: cdn.URL + "/blob", URLRange: reconwire.ByteRange{Start: 0, End: firstChunkEnd}, Range: reconwire.IndexRange{Start: 0, End: 1}},
			},
		},
	}
	// The original xorb is deliberately absent from upstream.xorbs: only
	// the presigned slice can succeed, and it is not the full xorb.
	casTS := httptest.NewServer(upstream.handler())

	ts, proxy := newTestServer(t, casTS)
	resp, err := http.Get(ts.URL + "/v2/reconstructions/" + fileHash.Hex())
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !proxy.Embedded.HasFileRecon(fileHash) {
		t.Fatal("partial-slice file was not cached")
	}
	if !proxy.Embedded.HasXorbFooter(syntheticHash) {
		t.Fatal("synthetic xorb from the cited slice was not cached")
	}
	if proxy.Embedded.HasXorbFooter(xorbHash) {
		t.Fatal("partial slice was stored under the original xorb hash")
	}
	if len(*ranges) == 0 {
		t.Fatal("presigned slice was never fetched")
	}

	// Once cached, the file is servable with upstream completely gone -
	// this is the property the dataset handoff depends on.
	casTS.Close()
	resp2, err := http.Get(ts.URL + "/v2/reconstructions/" + fileHash.Hex())
	if err != nil {
		t.Fatalf("offline GET error = %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("offline status = %d, want 200", resp2.StatusCode)
	}
}

// chunkURLRange returns the inclusive byte range covering chunks
// [start,end) in a footerless xorb, as fetch_info would describe it.
func chunkURLRange(entries []xorbformat.ChunkEntry, start, end int) reconwire.ByteRange {
	return reconwire.ByteRange{
		Start: entries[start].HeaderOffset,
		End:   entries[end-1].DataOffset + int64(entries[end-1].Header.CompressedLength) - 1,
	}
}

func testChunkPayloads(n int) [][]byte {
	payloads := make([][]byte, n)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte('a' + i%26)}, 32+i)
	}
	return payloads
}

func TestReconstruction_MidXorbSliceIsCachedAsSyntheticXorb(t *testing.T) {
	payloads := testChunkPayloads(22)
	blob, xorbHash := buildFooterlessXorb(t, payloads)
	entries, err := xorbformat.ScanChunks(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("ScanChunks() error = %v", err)
	}
	const start, end = 15, 21
	_, syntheticHash := buildFooterlessXorb(t, payloads[start:end])
	fileHash := hashFromByte(0xE5)

	cdn, ranges := cdnRangeServer(blob)
	defer cdn.Close()

	upstream := newRecoUpstream(fileHash.Hex())
	upstream.resp = &reconwire.ResponseV1{
		Terms: []reconwire.Term{
			{Hash: xorbHash.Hex(), Range: reconwire.IndexRange{Start: start, End: end}, UnpackedLength: uint32(sumLen(payloads[start:end]))},
		},
		FetchInfo: map[string][]reconwire.FetchInfoEntry{
			xorbHash.Hex(): {
				{URL: cdn.URL + "/blob", URLRange: chunkURLRange(entries, start, end), Range: reconwire.IndexRange{Start: start, End: end}},
			},
		},
	}
	casTS := httptest.NewServer(upstream.handler())

	ts, proxy := newTestServer(t, casTS)
	resp, err := http.Get(ts.URL + "/v2/reconstructions/" + fileHash.Hex())
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !proxy.Embedded.HasFileRecon(fileHash) {
		t.Fatal("mid-xorb file was not cached")
	}
	if !proxy.Embedded.HasXorbFooter(syntheticHash) {
		t.Fatal("synthetic xorb for the mid-xorb slice was not cached")
	}
	if proxy.Embedded.HasXorbFooter(xorbHash) {
		t.Fatal("partial slice was stored under the original xorb hash")
	}
	if len(*ranges) != 1 {
		t.Fatalf("CDN fetches = %d, want 1 (mid-xorb slices need no speculative full-xorb fetch)", len(*ranges))
	}

	casTS.Close()
	resp2, err := http.Get(ts.URL + "/v2/reconstructions/" + fileHash.Hex())
	if err != nil {
		t.Fatalf("offline GET error = %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("offline status = %d, want 200", resp2.StatusCode)
	}
}

func TestReconstruction_MultiplePartialTermsAreEachCached(t *testing.T) {
	payloads := testChunkPayloads(4)
	blob, xorbHash := buildFooterlessXorb(t, payloads)
	entries, err := xorbformat.ScanChunks(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("ScanChunks() error = %v", err)
	}
	_, firstHash := buildFooterlessXorb(t, payloads[0:2])
	_, secondHash := buildFooterlessXorb(t, payloads[3:4])
	fileHash := hashFromByte(0xE6)

	cdn, _ := cdnRangeServer(blob)
	defer cdn.Close()

	upstream := newRecoUpstream(fileHash.Hex())
	upstream.resp = &reconwire.ResponseV1{
		Terms: []reconwire.Term{
			{Hash: xorbHash.Hex(), Range: reconwire.IndexRange{Start: 0, End: 2}, UnpackedLength: uint32(sumLen(payloads[0:2]))},
			{Hash: xorbHash.Hex(), Range: reconwire.IndexRange{Start: 3, End: 4}, UnpackedLength: uint32(sumLen(payloads[3:4]))},
		},
		FetchInfo: map[string][]reconwire.FetchInfoEntry{
			xorbHash.Hex(): {
				{URL: cdn.URL + "/blob", URLRange: chunkURLRange(entries, 0, 2), Range: reconwire.IndexRange{Start: 0, End: 2}},
				{URL: cdn.URL + "/blob", URLRange: chunkURLRange(entries, 3, 4), Range: reconwire.IndexRange{Start: 3, End: 4}},
			},
		},
	}
	casTS := httptest.NewServer(upstream.handler())

	ts, proxy := newTestServer(t, casTS)
	resp, err := http.Get(ts.URL + "/v2/reconstructions/" + fileHash.Hex())
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !proxy.Embedded.HasFileRecon(fileHash) {
		t.Fatal("multi-term file was not cached")
	}
	for name, h := range map[string]struct {
		hash string
	}{"first": {firstHash.Hex()}, "second": {secondHash.Hex()}} {
		parsed, err := merklehash.FromHex(h.hash)
		if err != nil {
			t.Fatalf("%s: FromHex() error = %v", name, err)
		}
		if !proxy.Embedded.HasXorbFooter(parsed) {
			t.Errorf("%s synthetic xorb was not cached", name)
		}
	}
	if proxy.Embedded.HasXorbFooter(xorbHash) {
		t.Fatal("partial slices were stored under the original xorb hash")
	}

	casTS.Close()
	resp2, err := http.Get(ts.URL + "/v2/reconstructions/" + fileHash.Hex())
	if err != nil {
		t.Fatalf("offline GET error = %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("offline status = %d, want 200", resp2.StatusCode)
	}
}

func TestReconstruction_UnexactPartialCoverageRelaysLive(t *testing.T) {
	payloads := testChunkPayloads(22)
	blob, xorbHash := buildFooterlessXorb(t, payloads)
	entries, err := xorbformat.ScanChunks(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("ScanChunks() error = %v", err)
	}
	fileHash := hashFromByte(0xE7)

	cdn, _ := cdnRangeServer(blob)
	defer cdn.Close()

	upstream := newRecoUpstream(fileHash.Hex())
	upstream.resp = &reconwire.ResponseV1{
		Terms: []reconwire.Term{
			{Hash: xorbHash.Hex(), Range: reconwire.IndexRange{Start: 15, End: 21}, UnpackedLength: uint32(sumLen(payloads[15:21]))},
		},
		FetchInfo: map[string][]reconwire.FetchInfoEntry{
			xorbHash.Hex(): {
				// Covers chunks 15-17 only: not enough for the term.
				{URL: cdn.URL + "/blob", URLRange: chunkURLRange(entries, 15, 18), Range: reconwire.IndexRange{Start: 15, End: 18}},
			},
		},
	}
	casTS := httptest.NewServer(upstream.handler())
	defer casTS.Close()

	ts, proxy := newTestServer(t, casTS)
	resp, err := http.Get(ts.URL + "/v1/reconstructions/" + fileHash.Hex())
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (must relay, not fail the download)", resp.StatusCode)
	}
	if proxy.Embedded.HasFileRecon(fileHash) {
		t.Fatal("file with unexact coverage was cached anyway")
	}
}

func sumLen(payloads [][]byte) int {
	n := 0
	for _, p := range payloads {
		n += len(p)
	}
	return n
}

// TestReconstruction_SupersetFetchInfoGroupIsSharedByTerms matches the
// real dataset shape: one fetch_info entry covers the chunks for several
// terms (and may include chunks outside any single term). The proxy must
// cache that whole contiguous group once as a synthetic xorb and map
// every term into it, rather than rejecting coverage that is not an
// exact per-term match.
func TestReconstruction_SupersetFetchInfoGroupIsSharedByTerms(t *testing.T) {
	payloads := testChunkPayloads(22)
	blob, xorbHash := buildFooterlessXorb(t, payloads)
	entries, err := xorbformat.ScanChunks(bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("ScanChunks() error = %v", err)
	}
	_, syntheticHash := buildFooterlessXorb(t, payloads[12:22])
	fileHash := hashFromByte(0xE8)

	cdn, ranges := cdnRangeServer(blob)
	defer cdn.Close()

	upstream := newRecoUpstream(fileHash.Hex())
	upstream.resp = &reconwire.ResponseV1{
		Terms: []reconwire.Term{
			{Hash: xorbHash.Hex(), Range: reconwire.IndexRange{Start: 15, End: 18}, UnpackedLength: uint32(sumLen(payloads[15:18]))},
			{Hash: xorbHash.Hex(), Range: reconwire.IndexRange{Start: 18, End: 21}, UnpackedLength: uint32(sumLen(payloads[18:21]))},
		},
		FetchInfo: map[string][]reconwire.FetchInfoEntry{
			xorbHash.Hex(): {
				{URL: cdn.URL + "/blob", URLRange: chunkURLRange(entries, 12, 22), Range: reconwire.IndexRange{Start: 12, End: 22}},
			},
		},
	}
	casTS := httptest.NewServer(upstream.handler())

	ts, proxy := newTestServer(t, casTS)
	resp, err := http.Get(ts.URL + "/v2/reconstructions/" + fileHash.Hex())
	if err != nil {
		t.Fatalf("GET error = %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if !proxy.Embedded.HasFileRecon(fileHash) {
		t.Fatal("file with superset fetch_info was not cached")
	}
	if !proxy.Embedded.HasXorbFooter(syntheticHash) {
		t.Fatal("synthetic xorb for the shared fetch_info group was not cached")
	}
	if proxy.Embedded.HasXorbFooter(xorbHash) {
		t.Fatal("partial group was stored under the original xorb hash")
	}
	if len(*ranges) != 1 {
		t.Fatalf("CDN fetches = %d, want 1 (one shared group, not one per term)", len(*ranges))
	}

	casTS.Close()
	resp2, err := http.Get(ts.URL + "/v2/reconstructions/" + fileHash.Hex())
	if err != nil {
		t.Fatalf("offline GET error = %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("offline status = %d, want 200", resp2.StatusCode)
	}
}
