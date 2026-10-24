# `github.com/guilt/xet-server/internal/storage`

```
package storage // import "github.com/guilt/xet-server/internal/storage"

Package storage defines a backend-agnostic content-addressed object store.
Chunks and xorbs are both stored as opaque blobs keyed by content hash; the
same interface is satisfied by a local filesystem store (storage/fsstore) and an
S3-compatible store (storage/s3store), so the CAS server can run against either
without any caller-side branching.

Package storage's VerifyingStore lives in this file rather than storage.go to
keep the core interface definitions separate from this optional decorator.

VARIABLES

var ErrContentMismatch = errors.New("storage: dedup hit content differs from stored blob")
    ErrContentMismatch is returned (via errors.Is) by VerifyingStore.Put
    when a dedup hit's incoming content differs from what's already stored
    under the same key - a hash collision or storage corruption, since two
    different byte sequences should never produce the same content hash. Unlike
    ErrSizeMismatch, this is never a normal client protocol error; it always
    indicates something worth an operator's attention. See VerifyingStore's doc
    comment.

var ErrNotFound = errors.New("storage: blob not found")
    ErrNotFound is returned (via errors.Is) by Get/GetRange when no blob exists
    under the requested key. Every backend must wrap its native not-found signal
    (os.ErrNotExist, an S3 404) in this sentinel so callers can branch on it
    without knowing which backend is in use.

var ErrSizeMismatch = errors.New("storage: reader did not match declared size")
    ErrSizeMismatch is returned (via errors.Is) by Put when the number of bytes
    actually read from r does not match the declared size. This is a client
    protocol error (a wrong Content-Length or a truncated body), not a storage
    fault; the caller should treat it as non-retryable without a corrected size.


TYPES

type Deleter interface {
	Delete(ctx context.Context, key string) error
}
    Deleter is an optional capability: backends that support removing a
    previously-stored blob implement it. Not part of the core Store interface
    since not every caller needs delete (the Xet Data API's chunk store,
    for instance, never removes anything) - this exists for callers like a
    storage-budget eviction sweep that do. Deleting an already-absent key is not
    an error (idempotent).

type Enumerator interface {
	Enumerate(ctx context.Context, fn func(key string, size int64, modTime time.Time) error) error
}
    Enumerator is an optional capability: backends that can list every blob they
    hold implement it, so a caller that owns the store's lifecycle (casserver's
    garbage collector) can find blobs no index references any more - a xorb
    whose files were all dropped, or one uploaded just before a crash that lost
    the snapshot naming it. Like Sizer this is a walk over everything stored,
    meant for an occasional sweep, never a request hot path.

    fn is called once per completed blob with its key, size and last
    modification time; an in-flight upload's staging file is not a blob and is
    skipped. Returning an error from fn stops the walk and returns that error.

type Sizer interface {
	TotalBytes(ctx context.Context) (int64, error)
}
    Sizer is an optional capability: backends that can report the total bytes
    currently stored implement it, so a caller (e.g. an eviction sweep) can tell
    whether it's over a size budget without maintaining its own running total
    independently of the backend's actual state. This is expected to be called
    on a slow poll interval (minutes), not a hot path - backends are free to
    implement it by walking/listing everything they hold each call.

type Store interface {
	// Put streams exactly size bytes from r into key if not already
	// present. Returns true if the blob was newly written, false if it
	// already existed (deduplicated) - in the deduplicated case, r is
	// drained/ignored without being stored again.
	Put(ctx context.Context, key string, r io.Reader, size int64) (written bool, err error)

	// Get returns a reader for the full blob stored under key. The caller
	// must Close it. Returns an error satisfying errors.Is(err,
	// ErrNotFound) if no blob exists under key.
	Get(ctx context.Context, key string) (io.ReadCloser, error)

	// GetRange returns a reader for [offset, offset+length) of the blob
	// stored under key. The caller must Close it. Backends that cannot do
	// a partial read natively may fall back to a full read followed by a
	// bounded copy. Returns an error satisfying errors.Is(err,
	// ErrNotFound) if no blob exists under key.
	GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error)

	// Has reports whether a blob is already stored under key.
	Has(ctx context.Context, key string) (bool, error)
}
    Store is a content-addressed blob store: Put is a no-op if the key already
    exists (the basis for dedup), Get/GetRange stream back what was stored,
    and Has checks existence without transferring data.

    Put is atomic with respect to failure: if r returns an error, ctx is
    canceled, or the read stops short of size, no partial blob is left visible
    under key - implementations must stage writes (e.g. a temp file renamed
    into place, or an upload that is only finalized on success) so a caller can
    safely retry the same key after a failed attempt without a prior partial
    write corrupting the retry. Get/GetRange never observe a partially-written
    blob as a result.

func NewVerifyingStore(inner Store) Store
    NewVerifyingStore wraps inner. The returned *VerifyingStore implements
    whichever of Deleter, Sizer, and URLPresigner inner itself implements
    - wrapping a backend that lacks one of these (e.g. fsstore has no
    URLPresigner) must not make it appear to gain that capability, or callers
    that type-assert for it (casserver's presigned-URL fallback, eviction's
    Sweeper) would be silently misled. See the capabilityShim types below for
    how this is done without VerifyingStore itself unconditionally implementing
    all three.

type URLPresigner interface {
	// PresignGet returns a URL that, when fetched with a plain GET within
	// expirySeconds, returns the blob stored under key.
	PresignGet(ctx context.Context, key string, expirySeconds int) (string, error)
}
    URLPresigner is an optional capability: backends that can serve bytes
    directly to a client (e.g. S3/MinIO) implement it so the CAS server can hand
    out a presigned URL instead of proxying the bytes itself. Backends without a
    native presign mechanism (e.g. the filesystem store) simply don't implement
    this interface; callers type-assert for it.

type Unwrapper interface {
	Unwrap() Store
}
    Unwrapper is implemented by a Store that decorates another one
    (VerifyingStore) so a caller needing a capability the decorator does not
    forward can reach the backend underneath.

type VerifyingStore struct {
	Inner Store
}
    VerifyingStore wraps a Store to add an opt-in verification pass on every
    dedup hit: when Put finds key already exists, instead of trusting the
    content hash alone (the default, and by far the cheaper, behavior - see
    Store's own doc comment), it reads the existing stored blob and the incoming
    reader concurrently and compares them chunk-by-chunk, bailing at the first
    mismatch rather than reading either side in full once a difference is found.

    This exists purely as defense-in-depth against a hash collision or
    undetected storage-layer corruption - both exceedingly unlikely with BLAKE3,
    but "exceedingly unlikely" is a probability, not a guarantee, and this
    project would rather refuse a write it can't vouch for than silently trust a
    hash match that turns out to be wrong. It is deliberately NOT the default:
    it doubles I/O for every dedup hit (which is the common case for a healthy,
    working-as-intended deployment), so wrapping a Store with this is an
    explicit opt-in (see cmd/xetd's -verify-dedup flag), not something every
    caller pays for.

    If the incoming content doesn't match on a dedup hit, Put returns an error
    satisfying errors.Is(err, ErrContentMismatch) and does NOT overwrite the
    existing stored blob - a mismatch means something is already wrong (a
    collision or corruption), and blindly overwriting would destroy the only
    evidence of which side is actually correct without fixing anything.

    A key that does not yet exist passes straight through to Inner.Put with no
    extra reads of any kind - the non-dedup-hit path costs nothing beyond what
    Inner.Put itself costs, whether or not verification is enabled.

func (v *VerifyingStore) Get(ctx context.Context, key string) (io.ReadCloser, error)

func (v *VerifyingStore) GetRange(ctx context.Context, key string, offset, length int64) (io.ReadCloser, error)

func (v *VerifyingStore) Has(ctx context.Context, key string) (bool, error)

func (v *VerifyingStore) Put(ctx context.Context, key string, r io.Reader, size int64) (written bool, err error)
    Put implements the verify-on-dedup-hit behavior described on
    VerifyingStore's doc comment.

func (v *VerifyingStore) Unwrap() Store
    Unwrap implements Unwrapper: the backend underneath, for a caller
    that needs a capability this decorator does not forward (Enumerator,
    used by casserver's garbage collector). Every capability shim below embeds
    *VerifyingStore, so all of them expose it.
```
