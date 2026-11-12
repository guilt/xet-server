package casserver

// reconcile.go: repair snapshot-restored xorb metadata against the actual
// blobs on disk. A snapshot is only an index; the content-addressed blob is
// the source of truth. An older build (or a partially-migrated snapshot) can
// leave xorbRawLength recorded with a size that no longer matches the stored
// bytes even though the blob itself still hashes correctly under its name.
// Serving a Range from that stale length silently truncates the response
// (the client sees "unexpected end of file") or 416s a valid range, so
// startup reconciles every known xorb against storage before listening.

import (
	"context"
	"log/slog"
	"time"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/storage"
)

// ReconcileXorbLengths corrects xorbRawLength from the actual stored blob
// size and invalidates footers for any entry whose size changed (forcing the
// footer to be re-derived from the real bytes on next use). Entries whose
// blob is gone are dropped entirely, along with any file reconstruction that
// referenced them, so a proxy refetches instead of advertising a
// reconstruction it can no longer serve.
//
// It is safe to call once at startup after LoadSnapshot, before serving
// traffic. Backends without storage.Enumerator (and wrapped stores exposing
// one via storage.Unwrapper) are left untouched.
func (s *Server) ReconcileXorbLengths(ctx context.Context) {
	store := s.xorbs
	if u, ok := store.(storage.Unwrapper); ok {
		store = u.Unwrap()
	}
	enum, ok := store.(storage.Enumerator)
	if !ok {
		return
	}

	actual := make(map[merklehash.Hash]int64)
	if err := enum.Enumerate(ctx, func(key string, size int64, _ time.Time) error {
		hash, err := merklehash.FromHex(key)
		if err != nil {
			return nil
		}
		actual[hash] = size
		return nil
	}); err != nil {
		slog.Warn("casserver: xorb reconciliation scan failed", "error", err)
		return
	}

	var corrected, missing int
	missingHashes := make(map[merklehash.Hash]bool)
	s.xorbMu.Lock()
	for hash, recorded := range s.xorbRawLength {
		size, present := actual[hash]
		if !present {
			delete(s.xorbFooters, hash)
			delete(s.xorbRawLength, hash)
			delete(s.xorbLastAccess, hash)
			missingHashes[hash] = true
			missing++
			continue
		}
		if size != recorded {
			s.xorbRawLength[hash] = size
			// Force xorbMeta to re-derive the footer from the real bytes.
			delete(s.xorbFooters, hash)
			corrected++
		}
	}
	s.xorbMu.Unlock()

	if len(missingHashes) > 0 {
		s.fileReconMu.Lock()
		for fileID, entries := range s.fileRecon {
			for _, e := range entries {
				if missingHashes[e.XorbHash] {
					delete(s.fileRecon, fileID)
					break
				}
			}
		}
		s.fileReconMu.Unlock()
	}

	if corrected > 0 || missing > 0 {
		slog.Warn("casserver: reconciled xorb metadata against storage",
			"corrected_lengths", corrected, "missing_blobs", missing)
	}
}
