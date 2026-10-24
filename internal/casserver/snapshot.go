// Package casserver's snapshot.go implements Server's persistence: a
// periodic (and shutdown-time) atomic write of every in-memory index to a
// single JSON file, and a load of that file on startup. This is
// deliberately NOT a write-ahead log - writes between snapshots are lost
// if the process is killed (not just if it exits cleanly); see
// docs/PROTOCOL.md's persistence section for the full tradeoff writeup
// and why this was chosen anyway (atomic-swap is simple, needs no new
// dependency, and reuses the exact staging-file-then-rename pattern
// storage/fsstore.Store.Put already relies on for the same reason: a
// reader must never observe a half-written result).
package casserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/guilt/xet-server/internal/merklehash"
	"github.com/guilt/xet-server/internal/shardformat"
	"github.com/guilt/xet-server/internal/xorbformat"
)

// snapshot is the full on-disk representation of Server's in-memory
// state. Every field here corresponds to one of Server's index maps -
// adding a new index to Server means adding a field here and a line in
// Snapshot()/restoreFrom(), or it silently won't survive a restart.
type snapshot struct {
	// Version guards against loading a snapshot written by an
	// incompatible future format; bump it if a field's meaning changes
	// (not just when a field is added - additive changes stay readable by
	// older code that just ignores the new field via encoding/json's
	// default unknown-field tolerance).
	Version int `json:"version"`

	FileRecon     map[merklehash.Hash][]shardformat.FileDataSequenceEntry `json:"file_recon"`
	XorbFooters   map[merklehash.Hash]xorbformat.FooterV1                 `json:"xorb_footers"`
	XorbRawLength map[merklehash.Hash]int64                               `json:"xorb_raw_length"`
	SHA256ToXet   map[string]merklehash.Hash                              `json:"sha256_to_xet"`

	// ChunkHashToShard maps each chunk hash to the CONTENT HASH of the
	// shard body that references it (was `[]byte` in v1 - the raw shard
	// bytes duplicated per referencing chunk, which made json.Marshal
	// re-emit the same multi-MB body once per chunk and OOM the snapshot
	// goroutine on any repo with >~1M chunks). ShardBodies keeps one
	// copy of each unique shard body, so the serialized snapshot size is
	// O(unique shards + chunks) instead of O(shards × chunks).
	ChunkHashToShard map[merklehash.Hash]merklehash.Hash `json:"chunk_hash_to_shard"`
	ShardBodies      map[merklehash.Hash][]byte          `json:"shard_bodies"`

	// XorbLastAccess is when each xorb was last uploaded, fetched, or
	// listed in a global-dedup answer. It used to be deliberately left
	// out (for eviction, a reset to zero on restart only made every
	// xorb equally stale once), but the garbage collector's grace
	// period is measured from it, and a restart that forgot a xorb was
	// advertised yesterday would let GC delete what a client's cache
	// still points at. Additive (a v2 snapshot without it loads with
	// zero times, which GC treats as older than any grace).
	// xorbInFlight stays unpersisted: nothing is in flight across a
	// restart.
	XorbLastAccess map[merklehash.Hash]time.Time `json:"xorb_last_access,omitempty"`
}

// snapshotVersion is bumped whenever a field's meaning or type changes in
// a way old code can't safely read - LoadSnapshot warns and starts fresh
// on any mismatch (never fatal), keeping restarts non-crashy after a
// server upgrade at the cost of one-time recomputation of the affected
// indices. v2 changed ChunkHashToShard from map[Hash][]byte (raw shard
// body per chunk, unbounded json.Marshal blowup) to map[Hash]Hash paired
// with a shared ShardBodies map, so an old v1 snapshot's stored chunks
// can't be reused as-is.
const snapshotVersion = 2

// Snapshot serializes s's persistable indices to path via the same
// stage-to-temp-then-rename pattern storage/fsstore.Store.Put uses: a
// reader (a concurrent LoadSnapshot, or a crash mid-write followed by a
// restart) never observes a partially-written file, since os.Rename is
// atomic on the same filesystem.
//
// Each index's own mutex is taken (briefly, RLock only) to copy its
// current contents before releasing it and proceeding to the next index -
// this means Snapshot does NOT capture one single atomic instant across
// all indices simultaneously (a xorb upload completing between two of
// this function's per-index locks could appear in one snapshot section
// but not another, momentarily-inconsistent slice of the same snapshot
// file). That's an acceptable tradeoff for the same reason the per-index
// mutex split itself is: no code path anywhere in this server ever reads
// more than one of these indices under a single combined invariant, so a
// snapshot that's internally not perfectly instant-consistent across
// indices restores to a state no different from "a few requests landed
// slightly before or after this snapshot was taken" - which is already
// true of any periodic snapshot regardless of locking strategy.
func (s *Server) Snapshot(path string) error {
	snap := snapshot{Version: snapshotVersion}

	s.fileReconMu.RLock()
	snap.FileRecon = make(map[merklehash.Hash][]shardformat.FileDataSequenceEntry, len(s.fileRecon))
	for k, v := range s.fileRecon {
		snap.FileRecon[k] = v
	}
	s.fileReconMu.RUnlock()

	s.xorbMu.RLock()
	snap.XorbFooters = make(map[merklehash.Hash]xorbformat.FooterV1, len(s.xorbFooters))
	for k, v := range s.xorbFooters {
		snap.XorbFooters[k] = v
	}
	snap.XorbRawLength = make(map[merklehash.Hash]int64, len(s.xorbRawLength))
	for k, v := range s.xorbRawLength {
		snap.XorbRawLength[k] = v
	}
	snap.XorbLastAccess = make(map[merklehash.Hash]time.Time, len(s.xorbLastAccess))
	for k, v := range s.xorbLastAccess {
		if !v.IsZero() {
			snap.XorbLastAccess[k] = v
		}
	}
	s.xorbMu.RUnlock()

	s.sha256Mu.RLock()
	snap.SHA256ToXet = make(map[string]merklehash.Hash, len(s.sha256ToXet))
	for k, v := range s.sha256ToXet {
		snap.SHA256ToXet[k] = v
	}
	s.sha256Mu.RUnlock()

	s.chunkDedupMu.RLock()
	snap.ChunkHashToShard = make(map[merklehash.Hash]merklehash.Hash, len(s.chunkHashToShard))
	for k, v := range s.chunkHashToShard {
		snap.ChunkHashToShard[k] = v
	}
	snap.ShardBodies = make(map[merklehash.Hash][]byte, len(s.shardBodies))
	for k, v := range s.shardBodies {
		snap.ShardBodies[k] = v
	}
	s.chunkDedupMu.RUnlock()

	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("casserver: marshal snapshot: %w", err)
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("casserver: create snapshot temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("casserver: write snapshot temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("casserver: close snapshot temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("casserver: rename snapshot into place: %w", err)
	}
	return nil
}

// LoadSnapshot reads a snapshot previously written by Snapshot and
// restores s's indices from it. Intended to be called once, before s
// starts serving any traffic - it does not itself take any of s's
// per-index locks, since a freshly-constructed Server (via New) has no
// concurrent access to race against yet. A missing file at path is not
// an error (a fresh server with no prior snapshot); any other read/parse
// failure is returned so the caller can decide whether to start fresh or
// abort startup.
func (s *Server) LoadSnapshot(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("casserver: read snapshot: %w", err)
	}

	// Peek at just the version field first: an unknown-version snapshot
	// should never crash a restart. Fields whose meaning/type changed
	// won't decode into the current struct anyway (e.g. v1's
	// chunk_hash_to_shard was map[Hash][]byte, v2 is map[Hash]Hash), so
	// pushing on with a strict Unmarshal would surface as a confusing
	// parse error instead of the honest "old snapshot, starting fresh
	// for changed fields" story.
	var versionOnly struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(data, &versionOnly); err != nil {
		return fmt.Errorf("casserver: parse snapshot version: %w", err)
	}
	if versionOnly.Version != snapshotVersion {
		slog.Warn("casserver: snapshot version mismatch; starting fresh (xorbs on disk remain, indices will rebuild on next upload)",
			"snapshotVersion", versionOnly.Version, "expectedVersion", snapshotVersion, "path", path)
		return nil
	}

	var snap snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return fmt.Errorf("casserver: parse snapshot: %w", err)
	}

	if snap.FileRecon != nil {
		s.fileRecon = snap.FileRecon
	}
	if snap.XorbFooters != nil {
		s.xorbFooters = snap.XorbFooters
	}
	if snap.XorbRawLength != nil {
		s.xorbRawLength = snap.XorbRawLength
		// xorbLastAccess must have an entry for every restored xorb (the
		// eviction sweep's EvictionCandidates indexes xorbLastAccess by
		// the same keys as xorbRawLength) - backfilled to the zero Time
		// value, which sorts as "oldest" against any real access,
		// matching this file's top-level comment on why that's fine.
		for hash := range snap.XorbRawLength {
			if _, ok := s.xorbLastAccess[hash]; !ok {
				s.xorbLastAccess[hash] = snap.XorbLastAccess[hash]
			}
		}
	}
	if snap.SHA256ToXet != nil {
		s.sha256ToXet = snap.SHA256ToXet
	}
	if snap.ChunkHashToShard != nil {
		s.chunkHashToShard = snap.ChunkHashToShard
	}
	if snap.ShardBodies != nil {
		// Bodies are stored exactly as uploaded. A build before the keyed
		// dedup fix may have stored a footer-carrying (still raw-hash)
		// body instead; ReadShard accepts both shapes, and dedupAnswer
		// keys whatever it parses, so no migration is needed.
		for hash, body := range snap.ShardBodies {
			shard, err := shardformat.ReadShard(bytes.NewReader(body))
			if err != nil {
				continue
			}
			for _, x := range shard.Xorbs {
				if _, exists := s.xorbToShard[x.Header.XorbHash]; !exists {
					s.xorbToShard[x.Header.XorbHash] = hash
				}
			}
		}
		s.shardBodies = snap.ShardBodies
	}
	return nil
}
