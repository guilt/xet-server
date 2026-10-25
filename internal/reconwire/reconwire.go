// Package reconwire defines the wire types and response-building logic
// for GET /v1|v2/reconstructions/{file_id} - extracted out of
// internal/casserver so the clipping/grouping logic behind both
// endpoints has a single, independently-tested home. casserver's own
// handlers still do the clipping (calling BuildV1/BuildV2 directly);
// internal/proxycas only consumes the wire types (ResponseV1) to decode
// an upstream reconstruction response before feeding its terms into
// casserver.Server.IngestFileRecon - casserver's own delegation then
// runs the same BuildV1/BuildV2 logic over that ingested data. Because
// entries reaching BuildV1/BuildV2 by that path originated from an
// untrusted upstream response, physicalRange bounds-checks every
// chunk-index field it uses to index a footer's slices rather than
// trusting entries to already be internally consistent.
//
// This package has no notion of "where entries come from" - callers
// supply the file's entries and a FooterLookup callback (each server's
// own xorbFooters index has a different concrete type/locking strategy),
// keeping this package a pure function of its inputs.
package reconwire

import (
	"fmt"
	"sort"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/shardformat"
	"github.com/guilt/xet-server/internal/xorbformat"
)

// IndexRange mirrors xet-core's wire shape for a chunk-index range:
// Start inclusive, End exclusive.
type IndexRange struct {
	Start uint32 `json:"start"`
	End   uint32 `json:"end"`
}

// ByteRange mirrors xet-core's wire shape for a byte range: both ends
// inclusive.
type ByteRange struct {
	Start int64 `json:"start"`
	End   int64 `json:"end"` // inclusive
}

// Term is one file-reconstruction term: which xorb, which chunk range
// within it, and how many logical bytes it contributes.
type Term struct {
	Hash           string     `json:"hash"`
	Range          IndexRange `json:"range"`
	UnpackedLength uint32     `json:"unpacked_length"`
}

// FetchInfoEntry is one V1 fetch-info entry: a URL to fetch bytes from,
// the physical byte range within that URL's target, and the logical
// chunk-index range it corresponds to.
type FetchInfoEntry struct {
	URL      string     `json:"url"`
	URLRange ByteRange  `json:"url_range"`
	Range    IndexRange `json:"range"`
}

// ResponseV1 is GET /v1/reconstructions/{file_id}'s response body.
type ResponseV1 struct {
	OffsetIntoFirstRange int64                       `json:"offset_into_first_range"`
	Terms                []Term                      `json:"terms"`
	FetchInfo            map[string][]FetchInfoEntry `json:"fetch_info"`
}

// XorbRangeDescriptor is one chunk-range/byte-range pair within a
// XorbMultiRangeFetch - xet-core's XorbRangeDescriptor. Chunks uses
// exclusive end (matching IndexRange elsewhere); Bytes uses inclusive
// end (matching ByteRange elsewhere).
type XorbRangeDescriptor struct {
	Chunks IndexRange `json:"chunks"`
	Bytes  ByteRange  `json:"bytes"`
}

// XorbMultiRangeFetch is a single fetch URL covering possibly multiple
// disjoint chunk ranges for one xorb - xet-core's XorbMultiRangeFetch.
type XorbMultiRangeFetch struct {
	URL    string                `json:"url"`
	Ranges []XorbRangeDescriptor `json:"ranges"`
}

// ResponseV2 is GET /v2/reconstructions/{file_id}'s response body: same
// Terms/OffsetIntoFirstRange as V1, but Xorbs groups every chunk/byte
// range touched for a given xorb hash under that hash's key, each range
// paired with a fetch URL - the "multi-range" optimization the V2
// endpoint exists for.
type ResponseV2 struct {
	OffsetIntoFirstRange int64                            `json:"offset_into_first_range"`
	Terms                []Term                           `json:"terms"`
	Xorbs                map[string][]XorbMultiRangeFetch `json:"xorbs"`
}

// FooterLookup resolves a xorb hash to its known V1 footer, or ok=false
// if this server has no footer for it yet - the one piece of state
// BuildV1/BuildV2 need that isn't already in entries. The sole caller is
// casserver.Server (its own xorbFooters index); proxycas.Server never
// calls BuildV1/BuildV2 directly - it embeds a real casserver.Server and
// delegates reconstruction serving to it (see internal/proxycas's
// package doc comment).
type FooterLookup func(hash merklehash.Hash) (footer xorbformat.FooterV1, ok bool)

// FetchURLBuilder returns the URL a client should fetch hash's bytes
// from - casserver may hand out a presigned storage URL or its own
// byte-serving endpoint. The sole caller is casserver.Server; proxycas
// never constructs one of its own (see FooterLookup's doc comment) - it
// gets casserver's own byte-serving endpoint for free by delegating to
// its embedded Server, which is exactly the URL a caching proxy needs
// anyway (relaying a real presigned URL would bypass its cache).
type FetchURLBuilder func(hash merklehash.Hash) (string, error)

// ErrUnknownXorbFooter is returned (wrapped) by BuildV1/BuildV2 when
// entries references a xorb this server has no footer for - the
// server-side fault casserver surfaces as a 500 (a shard referenced a
// xorb whose upload session never completed). proxycas never sees this
// error directly: it only reaches BuildV1/BuildV2 indirectly, through
// its embedded casserver.Server's own handlers.
type ErrUnknownXorbFooter struct{ Hash merklehash.Hash }

func (e *ErrUnknownXorbFooter) Error() string {
	return fmt.Sprintf("reconstruction references unknown xorb %s", e.Hash.Hex())
}

// ErrChunkIndexOutOfRange is returned (wrapped) by BuildV1/BuildV2 when
// an entry's ChunkIndexStart/ChunkIndexEnd falls outside its xorb's own
// footer's chunk count. entries can originate from an untrusted upstream
// reconstruction response (internal/proxycas ingests one into
// casserver.Server.IngestFileRecon without independently re-deriving it -
// see this package's doc comment), so this is a real, reachable input
// validation failure, not just defensive programming: without this
// check, a malformed or hostile upstream response would index a slice
// out of bounds and crash the whole process.
type ErrChunkIndexOutOfRange struct {
	Hash                      merklehash.Hash
	ChunkIndexStart, ChunkEnd uint32
	FooterChunkCount          uint32
}

func (e *ErrChunkIndexOutOfRange) Error() string {
	return fmt.Sprintf("reconstruction term for xorb %s references chunk range [%d,%d), but its footer only has %d chunks",
		e.Hash.Hex(), e.ChunkIndexStart, e.ChunkEnd, e.FooterChunkCount)
}

// physicalRange computes the physical (compressed+header) byte range
// e's chunk-index range occupies within footer - see
// ErrChunkIndexOutOfRange's doc comment for why e's fields are
// validated against footer's actual chunk count rather than trusted.
func physicalRange(footer xorbformat.FooterV1, e shardformat.FileDataSequenceEntry) (start, end int64, err error) {
	chunkCount := uint32(len(footer.ChunkBoundaryOffsets))
	if e.ChunkIndexStart > e.ChunkIndexEnd || e.ChunkIndexEnd == 0 || e.ChunkIndexEnd > chunkCount {
		return 0, 0, &ErrChunkIndexOutOfRange{
			Hash:             e.XorbHash,
			ChunkIndexStart:  e.ChunkIndexStart,
			ChunkEnd:         e.ChunkIndexEnd,
			FooterChunkCount: chunkCount,
		}
	}
	start = 0
	if e.ChunkIndexStart > 0 {
		start = int64(footer.ChunkBoundaryOffsets[e.ChunkIndexStart-1])
	}
	end = int64(footer.ChunkBoundaryOffsets[e.ChunkIndexEnd-1])
	return start, end, nil
}

// FileSize returns entries' total logical (uncompressed) byte length -
// the file's full size, used both to clip a requested range and (by
// callers) to decide whether a cached fileRecon entry can serve a whole
// downstream request without an upstream call.
func FileSize(entries []shardformat.FileDataSequenceEntry) int64 {
	var size int64
	for _, e := range entries {
		size += int64(e.UnpackedSegmentBytes)
	}
	return size
}

// forEachClippedTerm walks entries, clipping to [rangeStart, rangeEnd]
// (inclusive) exactly as BuildV1/BuildV2 both need: skipping any term
// entirely outside the window, computing offsetIntoFirstRange from the
// first term actually kept, resolving each kept term's footer + physical
// byte range, and appending the term common to both response shapes -
// visit then handles the one part that actually differs between V1
// (one FetchInfoEntry per term) and V2 (grouped multi-range fetches per
// xorb).
func forEachClippedTerm(
	entries []shardformat.FileDataSequenceEntry,
	rangeStart, rangeEnd int64,
	lookupFooter FooterLookup,
	offsetIntoFirstRange *int64,
	appendTerm func(Term),
	visit func(e shardformat.FileDataSequenceEntry, physStart, physEnd int64) error,
) error {
	var fileOffset int64
	firstTerm := true
	for _, e := range entries {
		termStart := fileOffset
		termEnd := fileOffset + int64(e.UnpackedSegmentBytes) // exclusive
		fileOffset = termEnd

		if termEnd <= rangeStart || termStart > rangeEnd {
			continue
		}
		if firstTerm {
			*offsetIntoFirstRange = rangeStart - termStart
			firstTerm = false
		}

		footer, ok := lookupFooter(e.XorbHash)
		if !ok {
			return &ErrUnknownXorbFooter{Hash: e.XorbHash}
		}
		physStart, physEnd, err := physicalRange(footer, e)
		if err != nil {
			return err
		}

		appendTerm(Term{
			Hash:           e.XorbHash.Hex(),
			Range:          IndexRange{Start: e.ChunkIndexStart, End: e.ChunkIndexEnd},
			UnpackedLength: e.UnpackedSegmentBytes,
		})

		if err := visit(e, physStart, physEnd); err != nil {
			return err
		}
	}
	return nil
}

// BuildV1 clips entries to [rangeStart, rangeEnd] (inclusive) and builds
// the V1 response - the exact logic casserver.handleReconstructionV1's
// loop used to contain inline.
func BuildV1(entries []shardformat.FileDataSequenceEntry, rangeStart, rangeEnd int64, lookupFooter FooterLookup, fetchURL FetchURLBuilder) (ResponseV1, error) {
	resp := ResponseV1{FetchInfo: make(map[string][]FetchInfoEntry)}

	err := forEachClippedTerm(entries, rangeStart, rangeEnd, lookupFooter, &resp.OffsetIntoFirstRange,
		func(t Term) { resp.Terms = append(resp.Terms, t) },
		func(e shardformat.FileDataSequenceEntry, physStart, physEnd int64) error {
			url, err := fetchURL(e.XorbHash)
			if err != nil {
				return fmt.Errorf("build fetch URL: %w", err)
			}
			resp.FetchInfo[e.XorbHash.Hex()] = append(resp.FetchInfo[e.XorbHash.Hex()], FetchInfoEntry{
				URL:      url,
				URLRange: ByteRange{Start: physStart, End: physEnd - 1},
				Range:    IndexRange{Start: e.ChunkIndexStart, End: e.ChunkIndexEnd},
			})
			return nil
		})
	if err != nil {
		return ResponseV1{}, err
	}
	return resp, nil
}

// BuildV2 is BuildV1's V2 counterpart: same clipping, grouped by xorb
// hash with multiple ranges per fetch URL instead of V1's one entry per
// term - the exact logic casserver.handleReconstructionV2's loop used to
// contain inline.
func BuildV2(entries []shardformat.FileDataSequenceEntry, rangeStart, rangeEnd int64, lookupFooter FooterLookup, fetchURL FetchURLBuilder) (ResponseV2, error) {
	resp := ResponseV2{Xorbs: make(map[string][]XorbMultiRangeFetch)}
	fetchURLByXorb := make(map[string]string)

	err := forEachClippedTerm(entries, rangeStart, rangeEnd, lookupFooter, &resp.OffsetIntoFirstRange,
		func(t Term) { resp.Terms = append(resp.Terms, t) },
		func(e shardformat.FileDataSequenceEntry, physStart, physEnd int64) error {
			xorbHex := e.XorbHash.Hex()
			url, cached := fetchURLByXorb[xorbHex]
			if !cached {
				var err error
				url, err = fetchURL(e.XorbHash)
				if err != nil {
					return fmt.Errorf("build fetch URL: %w", err)
				}
				fetchURLByXorb[xorbHex] = url
			}

			descriptor := XorbRangeDescriptor{
				Chunks: IndexRange{Start: e.ChunkIndexStart, End: e.ChunkIndexEnd},
				Bytes:  ByteRange{Start: physStart, End: physEnd - 1},
			}

			fetches := resp.Xorbs[xorbHex]
			if len(fetches) == 0 || fetches[0].URL != url {
				resp.Xorbs[xorbHex] = append(fetches, XorbMultiRangeFetch{URL: url, Ranges: []XorbRangeDescriptor{descriptor}})
			} else {
				fetches[0].Ranges = append(fetches[0].Ranges, descriptor)
				resp.Xorbs[xorbHex] = fetches
			}
			return nil
		})
	if err != nil {
		return ResponseV2{}, err
	}
	normalizeV2Ranges(&resp)
	return resp, nil
}

// normalizeV2Ranges sorts each xorb's range list and merges overlapping or
// adjacent ranges. xet-core's reconstruction reader binary-searches /
// validates a term's chunk_start against this list; V1 emits one entry per
// term in file order, so a file with many terms against one shared xorb
// produces an unsorted list with duplicate and overlapping ranges. That is
// valid V1 data, but V2's single grouped list must be ordered and
// non-overlapping or the client can reject a perfectly good file with
// "chunk_start N not found in chunk_ranges ... for file term M".
func normalizeV2Ranges(resp *ResponseV2) {
	for hash, fetches := range resp.Xorbs {
		for i := range fetches {
			fetches[i].Ranges = mergeXorbRanges(fetches[i].Ranges)
		}
		resp.Xorbs[hash] = fetches
	}
}

func mergeXorbRanges(ranges []XorbRangeDescriptor) []XorbRangeDescriptor {
	if len(ranges) < 2 {
		return ranges
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Chunks.Start != ranges[j].Chunks.Start {
			return ranges[i].Chunks.Start < ranges[j].Chunks.Start
		}
		if ranges[i].Chunks.End != ranges[j].Chunks.End {
			return ranges[i].Chunks.End < ranges[j].Chunks.End
		}
		return ranges[i].Bytes.Start < ranges[j].Bytes.Start
	})
	merged := make([]XorbRangeDescriptor, 0, len(ranges))
	for _, r := range ranges {
		if len(merged) == 0 {
			merged = append(merged, r)
			continue
		}
		last := &merged[len(merged)-1]
		if r.Chunks.Start <= last.Chunks.End && r.Bytes.Start <= last.Bytes.End+1 {
			if r.Chunks.End > last.Chunks.End {
				last.Chunks.End = r.Chunks.End
			}
			if r.Bytes.Start < last.Bytes.Start {
				last.Bytes.Start = r.Bytes.Start
			}
			if r.Bytes.End > last.Bytes.End {
				last.Bytes.End = r.Bytes.End
			}
			continue
		}
		merged = append(merged, r)
	}
	return merged
}
