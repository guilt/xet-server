package hubserver

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/guilt/xet-server/internal/auth"
)

// handleLFSObject implements GET and HEAD
// /{repo_id}.git/info/lfs/objects/{oid}: the "basic" transfer download
// href handed out by handleLFSBatch. It streams the file's plain bytes,
// reconstructed from xorbs by the CAS, with Content-Length and Range
// support - git-lfs resumes an interrupted download with
// "Range: bytes=N-" and verifies the SHA-256 of what it received.
//
// Errors after the body has started cannot change the status any more;
// they are logged and the connection is cut short, which git-lfs's own
// size and hash checks turn into a retry or a clear failure.
func (s *Server) handleLFSObject(w http.ResponseWriter, r *http.Request, repo auth.Repo, oid string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		lfsError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.lfsAuthenticate(w, r, auth.ScopeRead, repo); !ok {
		return
	}
	if !isLFSOID(oid) {
		lfsError(w, "oid must be a lowercase hex SHA-256", http.StatusUnprocessableEntity)
		return
	}
	xetHash, known := s.CAS.XetHashForSHA256(oid)
	if !known {
		lfsError(w, "object not found", http.StatusNotFound)
		return
	}
	size, known := s.CAS.FileSize(xetHash)
	if !known {
		lfsError(w, "object not found", http.StatusNotFound)
		return
	}

	if missing, err := s.CAS.MissingXorbs(r.Context(), xetHash); err == nil && len(missing) > 0 {
		// Refuse before the first byte rather than abort mid-stream: on a
		// synced folder the xorbs are usually minutes away, and git-lfs
		// reports a 503 per object instead of a checksum failure.
		w.Header().Set("Retry-After", "15")
		lfsError(w, "content not yet available on this replica ("+strconv.Itoa(len(missing))+" xorb(s) still syncing); retry once the folder has synced", http.StatusServiceUnavailable)
		return
	}

	start, end, hasRange, err := parseLFSRange(r.Header.Get("Range"), size)
	if err != nil {
		w.Header().Set("Content-Range", "bytes */"+strconv.FormatInt(size, 10))
		lfsError(w, err.Error(), http.StatusRequestedRangeNotSatisfiable)
		return
	}

	length := size
	if hasRange {
		length = end - start + 1
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
	w.Header().Set("ETag", `"`+oid+`"`)
	if hasRange {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, size))
		w.WriteHeader(http.StatusPartialContent)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	if r.Method == http.MethodHead || length == 0 {
		return
	}

	// Verify what leaves the server on a whole-file download: the CAS
	// vouches for chunk hashes, but this is the one place the assembled
	// file meets the SHA-256 git-lfs named it by.
	if !hasRange {
		hasher := sha256.New()
		tee := teeWriter{w: w, h: hasher}
		if err := s.CAS.ReconstructFile(r.Context(), xetHash, 0, size-1, &tee); err != nil {
			s.abortLFSStream(r, oid, err)
			return
		}
		if got := hex.EncodeToString(hasher.Sum(nil)); got != oid {
			s.abortLFSStream(r, oid, fmt.Errorf("reconstructed content hashes to %s, not the requested oid", got))
		}
		return
	}
	if err := s.CAS.ReconstructFile(r.Context(), xetHash, start, end, w); err != nil {
		s.abortLFSStream(r, oid, err)
	}
}

// abortLFSStream logs a mid-body failure and closes the connection so
// the client sees a short read instead of a silently truncated 200.
func (s *Server) abortLFSStream(r *http.Request, oid string, err error) {
	if errors.Is(err, r.Context().Err()) && r.Context().Err() != nil {
		slog.Debug("hubserver: lfs download canceled by client", "oid", oid)
		return
	}
	slog.Error("hubserver: lfs download failed mid-stream", "oid", oid, "error", err)
	// Once headers are out, aborting the handler with http.ErrAbortHandler
	// is net/http's documented way to close the connection without a
	// stack trace, so the client sees a short read rather than a clean
	// end to a truncated body.
	panic(http.ErrAbortHandler)
}

type teeWriter struct {
	w interface{ Write([]byte) (int, error) }
	h interface{ Write([]byte) (int, error) }
}

func (t *teeWriter) Write(p []byte) (int, error) {
	t.h.Write(p)
	return t.w.Write(p)
}

// parseLFSRange parses a single-range "bytes=start-end" or open-ended
// "bytes=start-" header against total (the file size). Returns
// hasRange=false for an empty header. A malformed header is ignored (the
// HTTP spec says to serve the whole representation), while a well-formed
// but unsatisfiable one is an error the caller turns into a 416.
func parseLFSRange(header string, total int64) (start, end int64, hasRange bool, err error) {
	if header == "" {
		return 0, 0, false, nil
	}
	spec, ok := strings.CutPrefix(header, "bytes=")
	if !ok || strings.Contains(spec, ",") {
		return 0, 0, false, nil
	}
	first, last, ok := strings.Cut(spec, "-")
	if !ok {
		return 0, 0, false, nil
	}
	if first == "" {
		// Suffix range "bytes=-N": the last N bytes.
		n, perr := strconv.ParseInt(last, 10, 64)
		if perr != nil || n <= 0 {
			return 0, 0, false, nil
		}
		if n > total {
			n = total
		}
		if total == 0 {
			return 0, 0, false, errors.New("range not satisfiable: empty object")
		}
		return total - n, total - 1, true, nil
	}
	start, err = strconv.ParseInt(first, 10, 64)
	if err != nil || start < 0 {
		return 0, 0, false, nil
	}
	if last == "" {
		end = total - 1
	} else {
		end, err = strconv.ParseInt(last, 10, 64)
		if err != nil || end < start {
			return 0, 0, false, nil
		}
		if end >= total {
			end = total - 1
		}
	}
	if start >= total {
		return 0, 0, false, fmt.Errorf("range not satisfiable: start %d beyond size %d", start, total)
	}
	return start, end, true, nil
}
