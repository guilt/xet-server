package casserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/storage"
	"github.com/guilt/xet-server/internal/xorbformat"
)

// httpError writes an HTTP error response and logs it at a level matching
// its cause: a 5xx reflects a server-side fault worth surfacing at Warn by
// default, while a 4xx is a client protocol/input error - expected to
// happen under normal operation (a bad hash, a truncated upload) and only
// useful for debugging, so it logs at Debug to avoid every malformed
// request from a client spamming the default log level.
func httpError(w http.ResponseWriter, msg string, code int) {
	if code >= 500 {
		slog.Warn("casserver: request failed", "status", code, "error", msg)
	} else {
		slog.Debug("casserver: request rejected", "status", code, "error", msg)
	}
	http.Error(w, msg, code)
}

// maxXorbBytes caps a single xorb upload's body size. Real xet-core targets
// ~64 MiB per xorb before cutting a new one (MAX_XORB_BYTES in
// xet-core's constants), so this is generous headroom above what a
// well-behaved client ever sends in one xorb - its purpose here is purely
// to bound how large a temp file a single hostile/misbehaving request can
// force the server to stage, not to constrain normal traffic.
const maxXorbBytes = 128 * 1024 * 1024

// handleUploadXorb implements POST /v1/xorbs/{prefix}/{hash}: stream the
// serialized xorb body to a temp file (xorbformat.ScanChunks needs seek,
// which an HTTP request body doesn't support), then delegate to
// IngestXorb for validation/storage/indexing - see its doc comment for
// why real hf_xet clients upload xorbs without a footer, and why the
// hash is independently re-derived and verified rather than trusted.
func (s *Server) handleUploadXorb(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("prefix") != xorbPrefix {
		httpError(w, "unsupported xorb prefix", http.StatusBadRequest)
		return
	}
	claimedHash, err := hexParam(r, "hash")
	if err != nil {
		httpError(w, "invalid hash", http.StatusBadRequest)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxXorbBytes)

	written, err := s.IngestXorb(r.Context(), claimedHash, r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		switch {
		case errors.As(err, &maxBytesErr):
			httpError(w, "exceeds max xorb size or connection error: "+err.Error(), http.StatusRequestEntityTooLarge)
		case errors.Is(err, ErrMalformedXorb), errors.Is(err, ErrXorbHashMismatch):
			httpError(w, err.Error(), http.StatusBadRequest)
		default:
			if errors.Is(err, storage.ErrContentMismatch) {
				// A hash collision or storage-layer corruption - the two
				// possible causes of "same content hash, different actual
				// bytes" - is always worth an operator's attention,
				// distinct from the routine client-caused 5xx paths
				// httpError's normal Warn level covers. Only reachable
				// when -verify-dedup is enabled (see cmd/xetd);
				// storage.VerifyingStore never overwrites the existing
				// stored blob when this happens.
				slog.Error("casserver: dedup verification detected a content mismatch",
					"claimedHash", claimedHash.Hex(), "error", err)
			}
			httpError(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	writeJSON(w, uploadXorbResponse{WasInserted: written})
}

// ErrMalformedXorb is returned (wrapped) by IngestXorb when r's bytes
// don't parse as a valid chunk stream (see xorbformat.DeriveFooter) -
// maps to a 400 at handleUploadXorb's HTTP boundary.
var ErrMalformedXorb = errors.New("casserver: malformed xorb")

// ErrXorbHashMismatch is returned (wrapped) by IngestXorb when
// claimedHash doesn't match the hash independently computed from r's
// chunk contents - maps to a 400 at handleUploadXorb's HTTP boundary.
var ErrXorbHashMismatch = errors.New("casserver: xorb hash in URL does not match hash computed from chunk contents")

// IngestXorb validates, stores, and indexes a xorb's raw chunk-stream
// bytes (read from r, with no footer - see handleUploadXorb's doc
// comment on why: real hf_xet clients never send one) under
// claimedHash, exactly as a real client's upload would. Returns
// written=true if this was a new xorb (false if claimedHash was already
// present - Put's normal dedup semantics).
//
// Exported so a caller embedding this Server as a caching layer (e.g.
// internal/proxycas, wrapping this server instead of reimplementing its
// upload-validation/indexing logic independently) can feed it xorb bytes
// fetched from elsewhere - an upstream CAS response, not an HTTP
// request body - through the identical validation and storage path a
// real upload goes through, so anything this method accepts is
// guaranteed servable afterward the same way a directly-uploaded xorb
// is.
func (s *Server) IngestXorb(ctx context.Context, claimedHash merklehash.Hash, r io.Reader) (written bool, err error) {
	tmp, err := os.CreateTemp("", "xet-xorb-upload-*")
	if err != nil {
		return false, fmt.Errorf("stage upload: %w", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	size, err := io.Copy(tmp, r)
	if err != nil {
		return false, fmt.Errorf("read xorb body: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return false, fmt.Errorf("%w: %v", ErrMalformedXorb, err)
	}

	footer, computedHash, err := xorbformat.DeriveFooter(tmp)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrMalformedXorb, err)
	}
	if computedHash != claimedHash {
		return false, ErrXorbHashMismatch
	}

	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return false, fmt.Errorf("store xorb: %w", err)
	}
	s.gcMu.RLock()
	defer s.gcMu.RUnlock()
	written, err = s.xorbs.Put(ctx, claimedHash.Hex(), tmp, size)
	if err != nil {
		return false, fmt.Errorf("store xorb: %w", err)
	}

	s.xorbMu.Lock()
	s.xorbFooters[claimedHash] = footer
	s.xorbRawLength[claimedHash] = size
	s.xorbLastAccess[claimedHash] = time.Now()
	s.xorbMu.Unlock()

	return written, nil
}

// HasXorbFooter reports whether this server has a footer indexed for
// hash - a caller embedding this Server (see IngestXorb's doc comment)
// uses this to decide whether a reconstruction it's about to serve can
// be built entirely from local state, or needs to fetch/ingest the xorb
// first.
func (s *Server) HasXorbFooter(hash merklehash.Hash) bool {
	s.xorbMu.RLock()
	defer s.xorbMu.RUnlock()
	_, ok := s.xorbFooters[hash]
	return ok
}

// HasXorbBytes reports whether hash's raw bytes are present in this
// server's storage backend - distinct from HasXorbFooter (footer/size
// indexing and blob storage are updated together by IngestXorb/
// handleUploadXorb, but a caller embedding this Server may want to
// confirm both independently, e.g. after a restart with a stale index).
func (s *Server) HasXorbBytes(ctx context.Context, hash merklehash.Hash) (bool, error) {
	return s.xorbs.Has(ctx, hash.Hex())
}

// handleFetchXorb implements the byte-serving side of a fetch_info URL:
// GET /v1/xorbs/{prefix}/{hash}, honoring an HTTP Range header the same
// way a presigned S3 URL would.
func (s *Server) handleFetchXorb(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("prefix") != xorbPrefix {
		httpError(w, "unsupported xorb prefix", http.StatusBadRequest)
		return
	}
	hash, err := hexParam(r, "hash")
	if err != nil {
		httpError(w, "invalid hash", http.StatusBadRequest)
		return
	}

	_, total, known := s.xorbMeta(r.Context(), hash)
	if !known {
		http.NotFound(w, r)
		return
	}
	s.xorbMu.Lock()
	s.xorbLastAccess[hash] = time.Now()
	s.xorbInFlight[hash]++
	s.xorbMu.Unlock()
	defer func() {
		s.xorbMu.Lock()
		s.xorbInFlight[hash]--
		s.xorbMu.Unlock()
	}()

	start, end, hasRange, err := parseByteRange(r.Header.Get("Range"), total)
	if err != nil {
		httpError(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)
		return
	}

	contentLength := total
	var data io.ReadCloser
	if hasRange {
		contentLength = end - start + 1
		data, err = s.xorbs.GetRange(r.Context(), hash.Hex(), start, contentLength)
	} else {
		data, err = s.xorbs.Get(r.Context(), hash.Hex())
	}
	if err != nil {
		httpError(w, "fetch xorb: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer data.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	if hasRange {
		// Content-Type/Content-Length above must be set before this
		// WriteHeader call - Go snapshots headers at WriteHeader time, so
		// setting them afterward would silently drop Content-Length from
		// every ranged (206) response.
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))
		w.WriteHeader(http.StatusPartialContent)
	}
	io.Copy(w, data)
}

func (s *Server) handleHeadXorb(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("prefix") != xorbPrefix {
		httpError(w, "unsupported xorb prefix", http.StatusBadRequest)
		return
	}
	hash, err := hexParam(r, "hash")
	if err != nil {
		httpError(w, "invalid hash", http.StatusBadRequest)
		return
	}
	_, total, known := s.xorbMeta(r.Context(), hash)
	if !known {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Length", strconv.FormatInt(total, 10))
	w.WriteHeader(http.StatusOK)
}

// parseByteRange parses a single-range HTTP Range header with the three
// forms real clients actually send: "bytes=start-end", the open-ended
// "bytes=start-" (hf_xet uses this for reconstruction responses), and the
// suffix form "bytes=-length". Multi-range requests are intentionally not
// supported (this server serves one contiguous range per response).
// Inclusive end, per HTTP semantics. Returns hasRange=false if header is
// empty.
func parseByteRange(header string, total int64) (start, end int64, hasRange bool, err error) {
	if header == "" {
		return 0, 0, false, nil
	}
	const prefix = "bytes="
	if !strings.HasPrefix(header, prefix) {
		return 0, 0, false, fmt.Errorf("malformed Range header")
	}
	spec := strings.TrimSpace(header[len(prefix):])
	if spec == "" || strings.Contains(spec, ",") {
		return 0, 0, false, fmt.Errorf("malformed Range header")
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		return 0, 0, false, fmt.Errorf("malformed Range header")
	}
	startStr := strings.TrimSpace(spec[:dash])
	endStr := strings.TrimSpace(spec[dash+1:])

	// Suffix form: "bytes=-N" means the last N bytes.
	if startStr == "" {
		if endStr == "" || strings.Contains(endStr, "-") {
			return 0, 0, false, fmt.Errorf("malformed Range header")
		}
		n, parseErr := strconv.ParseInt(endStr, 10, 64)
		if parseErr != nil || n < 0 {
			return 0, 0, false, fmt.Errorf("malformed Range header")
		}
		if n == 0 || total <= 0 {
			return 0, 0, false, fmt.Errorf("range not satisfiable")
		}
		if n >= total {
			return 0, total - 1, true, nil
		}
		return total - n, total - 1, true, nil
	}

	s, parseErr := strconv.ParseInt(startStr, 10, 64)
	if parseErr != nil || s < 0 {
		return 0, 0, false, fmt.Errorf("malformed Range header")
	}
	if total <= 0 || s >= total {
		return 0, 0, false, fmt.Errorf("range not satisfiable")
	}
	// Open-ended form: "bytes=start-" means through EOF.
	if endStr == "" {
		return s, total - 1, true, nil
	}
	e, parseErr := strconv.ParseInt(endStr, 10, 64)
	if parseErr != nil || strings.Contains(endStr, "-") {
		return 0, 0, false, fmt.Errorf("malformed Range header")
	}
	if e < s {
		return 0, 0, false, fmt.Errorf("range not satisfiable")
	}
	if e >= total {
		e = total - 1
	}
	return s, e, true, nil
}
