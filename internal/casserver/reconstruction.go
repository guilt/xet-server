package casserver

// reconstruction.go dispatches GET /v1|v2/reconstructions/{file_id}:
// looks up fileID's shard-derived reconstruction entries, clips them to
// the requested byte range, and delegates the actual V1/V2 response
// shape to internal/reconwire (shared with internal/proxycas, which
// needs byte-identical clipping/grouping logic once it has a file's
// complete reconstruction cached - see reconwire's package doc comment).

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/reconwire"
	"github.com/guilt/xet-server/internal/shardformat"
	"github.com/guilt/xet-server/internal/storage"
	"github.com/guilt/xet-server/internal/xorbformat"
)

// reconstructionWindow looks up fileID's shard-derived reconstruction
// entries and clips the requested byte range against the file's total
// size, shared by both handleReconstructionV1 and handleReconstructionV2
// since both need the identical entries/range-window before diverging on
// how they shape the fetch-info portion of their response.
//
// found=false means fileID is unknown (caller should 404). found=true
// with a non-nil err means fileID is known but rangeHeader was
// unsatisfiable (caller should 416) - distinguishing these two cases is
// why this doesn't just return a single error.
func (s *Server) reconstructionWindow(fileID merklehash.Hash, rangeHeader string) (entries []shardformat.FileDataSequenceEntry, rangeStart, rangeEnd int64, found bool, err error) {
	s.fileReconMu.RLock()
	entries, found = s.fileRecon[fileID]
	s.fileReconMu.RUnlock()
	if !found {
		return nil, 0, 0, false, nil
	}

	fileSize := reconwire.FileSize(entries)
	start, end, hasRange, rangeErr := parseByteRange(rangeHeader, fileSize)
	if rangeErr != nil {
		return entries, 0, 0, true, rangeErr
	}
	if !hasRange {
		start, end = 0, fileSize-1
	}
	return entries, start, end, true, nil
}

// IngestFileRecon records fileID's complete reconstruction entries
// as if a shard had described it - for a caller embedding this Server
// as a caching layer (e.g. internal/proxycas) that learned a file's
// reconstruction from an upstream CAS response rather than from a real
// shard upload. entries must be the file's COMPLETE ordered term list
// (not a byte-range-clipped subset - see internal/proxycas's own
// handleReconstruction doc comment for why a Range-limited upstream
// response can never safely populate this): reconstructionWindow and
// every downstream reader assumes fileRecon[fileID] represents the
// whole file, and a caller that violates that would silently truncate
// every future request for it.
func (s *Server) IngestFileRecon(fileID merklehash.Hash, entries []shardformat.FileDataSequenceEntry) {
	s.gcMu.RLock()
	defer s.gcMu.RUnlock()
	s.fileReconMu.Lock()
	s.fileRecon[fileID] = entries
	s.fileReconMu.Unlock()
}

// HasFileRecon reports whether this server already has a complete
// reconstruction on file for fileID - a caller embedding this Server
// uses this to decide whether a reconstruction request can be served
// entirely from local state or needs an upstream fetch (+ IngestFileRecon)
// first.
func (s *Server) HasFileRecon(fileID merklehash.Hash) bool {
	s.fileReconMu.RLock()
	defer s.fileReconMu.RUnlock()
	_, ok := s.fileRecon[fileID]
	return ok
}

// handleReconstructionV1 implements GET /v1/reconstructions/{file_id}: looks
// up the file's shard-derived reconstruction entries, clips them to the
// requested byte range (via the standard HTTP Range header, inclusive end
// - real clients page through large files by re-requesting successively
// higher windows), and for each term resolves the referenced xorb's
// chunk-index range into a byte range (using that xorb's footer, indexed
// at upload time), then emits a fetch_info URL for each distinct xorb
// touched.
//
// Per the client's documented contract, a Range header whose start is at or
// past the file's end must get a 416 (mapped by hf_xet to "no more data,
// stop paging"), not an empty 200 - an empty-but-200 response would leave
// the client's sequential writer waiting for a term it will never receive.
func (s *Server) handleReconstructionV1(w http.ResponseWriter, r *http.Request) {
	fileID, err := hexParam(r, "file_id")
	if err != nil {
		httpError(w, "invalid file_id", http.StatusBadRequest)
		return
	}

	entries, rangeStart, rangeEnd, found, err := s.reconstructionWindow(fileID, r.Header.Get("Range"))
	if !found {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		httpError(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)
		return
	}

	baseURL := baseURLFromRequest(r)
	resp, err := reconwire.BuildV1(entries, rangeStart, rangeEnd, s.lookupXorbFooter, s.xorbFetchURLFor(r.Context(), baseURL))
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, resp)
}

// handleReconstructionV2 implements GET /v2/reconstructions/{file_id}: the
// multi-range-optimized reconstruction response - same terms/range-window
// logic as V1 (see reconstructionWindow), but groups every chunk/byte
// range touched for a given xorb under that xorb's single fetch URL,
// rather than V1's one fetchInfoEntry per term (so a file whose
// reconstruction touches the same xorb across several non-contiguous
// terms gets one xorb entry with multiple ranges, not several
// nearly-identical entries differing only by range). Response shape
// verified against xet-core's real QueryReconstructionResponseV2 struct
// and its update_260316_v2_reconstruction_multirange.md changelog - see
// docs/PROTOCOL.md's dedicated section on this endpoint for the story of
// why the "V1 vs V2" difference is purely response shape, not different
// underlying data.
func (s *Server) handleReconstructionV2(w http.ResponseWriter, r *http.Request) {
	fileID, err := hexParam(r, "file_id")
	if err != nil {
		httpError(w, "invalid file_id", http.StatusBadRequest)
		return
	}

	entries, rangeStart, rangeEnd, found, err := s.reconstructionWindow(fileID, r.Header.Get("Range"))
	if !found {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		httpError(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)
		return
	}

	baseURL := baseURLFromRequest(r)
	resp, err := reconwire.BuildV2(entries, rangeStart, rangeEnd, s.lookupXorbFooter, s.xorbFetchURLFor(r.Context(), baseURL))
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, resp)
}

// lookupXorbFooter is reconwire.FooterLookup's implementation against
// this server's own xorbFooters index - also bumps xorbLastAccess (see
// the comment on the logic this replaces for why): a client requesting
// reconstruction is about to fetch this xorb, either from our own
// byte-serving endpoint (which also bumps this on the actual fetch) or
// from a presigned URL, which we'd otherwise never observe at all.
// Bumping here means eviction sees "about to be needed" even in the
// presigned-URL case.
func (s *Server) lookupXorbFooter(hash merklehash.Hash) (xorbformat.FooterV1, bool) {
	f, _, known := s.xorbMeta(context.Background(), hash)
	if !known {
		return xorbformat.FooterV1{}, false
	}
	s.xorbMu.Lock()
	s.xorbLastAccess[hash] = time.Now()
	s.xorbMu.Unlock()
	return f, true
}

// xorbFetchURLFor returns a reconwire.FetchURLBuilder bound to ctx and
// baseURL - reconwire's function-typed callback signature takes no
// context/baseURL of its own (those are HTTP-request-scoped, not part of
// the pure clipping logic reconwire implements).
func (s *Server) xorbFetchURLFor(ctx context.Context, baseURL string) reconwire.FetchURLBuilder {
	return func(hash merklehash.Hash) (string, error) {
		return s.xorbFetchURL(ctx, hash, baseURL)
	}
}

// xorbFetchURL returns a presigned URL if the storage backend supports it
// (storage.URLPresigner - e.g. S3/MinIO), otherwise a URL pointing back at
// this server's own byte-serving endpoint - signed with a read token for
// the requesting principal when SetFetchURLSigner is configured, since
// the client fetches it with no Authorization header.
func (s *Server) xorbFetchURL(ctx context.Context, xorbHash merklehash.Hash, baseURL string) (string, error) {
	if presigner, ok := s.xorbs.(storage.URLPresigner); ok {
		return presigner.PresignGet(ctx, xorbHash.Hex(), 3600)
	}
	u := fmt.Sprintf("%s/v1/xorbs/%s/%s", baseURL, xorbPrefix, xorbHash.Hex())
	if s.urlTokenMinter != nil {
		if principal, ok := ctx.Value(principalKey{}).(auth.Principal); ok {
			token, _, err := s.urlTokenMinter.MintToken(auth.ScopeRead, principal.Subject(), auth.RepoOf(principal), s.urlTokenTTL)
			if err != nil {
				return "", fmt.Errorf("sign xorb fetch url: %w", err)
			}
			u += "?" + urlTokenParam + "=" + url.QueryEscape(token)
		}
	}
	return u, nil
}

func baseURLFromRequest(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}

// handleChunkDedup implements GET /v1/chunks/{prefix}/{hash}: the real
// wire contract (per xet-core's openapi/cas.openapi.yaml and
// query_for_global_dedup_shard in xet-core's remote_client.rs) is to
// return the raw bytes of whichever previously-uploaded shard referenced
// this chunk hash - the client parses that shard itself
// (filter_cas_chunks_for_global_dedup) to discover which of its own
// chunks it can skip re-uploading. 404 if no uploaded shard has ever
// referenced this chunk hash.
func (s *Server) handleChunkDedup(w http.ResponseWriter, r *http.Request) {
	if !isChunkDedupPrefix(r.PathValue("prefix")) {
		httpError(w, "unsupported chunk-dedup prefix", http.StatusBadRequest)
		return
	}
	hash, err := hexParam(r, "hash")
	if err != nil {
		httpError(w, "invalid hash", http.StatusBadRequest)
		return
	}

	shardBytes, known, err := s.dedupAnswer(hash)
	if !known && s.rescanOnMiss() {
		shardBytes, known, err = s.dedupAnswer(hash)
	}
	if err != nil {
		httpError(w, "build dedup answer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !known || shardBytes == nil {
		// !known: no uploaded shard has ever referenced this chunk.
		// shardBytes == nil: the shard's body was evicted or never
		// populated - either way the client can't dedup against a body
		// we no longer have, and a 404 correctly signals "no dedup
		// available" (the same outcome as no shard entry at all).
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(shardBytes)))
	w.Write(shardBytes)
}

// handleTelemetry is a fire-and-forget ack: the real client never retries
// or inspects the response body.
func (s *Server) handleTelemetry(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
