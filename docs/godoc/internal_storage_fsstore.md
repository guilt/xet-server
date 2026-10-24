# `github.com/guilt/xet-server/internal/storage/fsstore`

```
package fsstore // import "github.com/guilt/xet-server/internal/storage/fsstore"

Package fsstore implements storage.Store as a content-addressed filesystem
directory. Blobs are keyed by their content hash and laid out as
<root>/<hash[:2]>/<hash[2:4]>/<hash> to avoid huge flat directories.

TYPES

type Store struct {
	Root string
}

func New(root string) (*Store, error)

func (s *Store) Delete(_ context.Context, key string) error
    Delete removes the blob stored under key. Deleting an already-absent key
    is not an error, matching the interface's idempotent-delete contract (an
    eviction sweep racing a concurrent Delete of the same key, or retrying after
    a partial failure, shouldn't need to distinguish "already gone" from "just
    removed").

func (s *Store) Enumerate(ctx context.Context, fn func(key string, size int64, modTime time.Time) error) error
    Enumerate implements storage.Enumerator: every completed blob under Root,
    by key, size and modification time. Staging files are skipped (and reaped
    once older than staleTempFileAge - see TotalBytes, whose walk this is).

func (s *Store) Get(_ context.Context, key string) (io.ReadCloser, error)

func (s *Store) GetRange(_ context.Context, key string, offset, length int64) (io.ReadCloser, error)

func (s *Store) Has(_ context.Context, key string) (bool, error)

func (s *Store) Put(ctx context.Context, key string, r io.Reader, size int64) (written bool, err error)
    Put stages the write to a per-attempt temp file and only renames it into
    place once size bytes have been fully copied from r. If r errs, ctx is
    canceled, or the copy stops short of size, the temp file is removed and no
    partial blob is ever visible under key - a caller can retry Put with a fresh
    reader afterward with no cleanup of its own required.

    The temp file is created via os.CreateTemp (not a fixed PID-based name):
    concurrent Put calls for the *same* key within one process are a normal,
    expected race (e.g. several clients uploading an identical xorb at once -
    see TestAdversarial_ConcurrentUploadsOfSameXorb), and each needs its own
    independent staging file rather than colliding on one shared path.

func (s *Store) TotalBytes(ctx context.Context) (int64, error)
    TotalBytes walks the store's root and sums the size of every *completed*
    stored blob. This is an O(number of blobs) directory walk, not a cached
    counter - fine for a slow poll (an eviction sweep runs every few minutes at
    most), but callers should not call this on any request hot path.

    In-flight upload staging files (os.CreateTemp's ".tmp-*" names - see Put)
    are excluded from the total: counting them would inflate the measured size
    by uploads that haven't committed yet and may never complete, skewing an
    eviction budget check upward for no real storage that will persist. But a
    temp file left behind by a process that crashed or was killed mid-upload
    (Put's own os.Remove(tmp) cleanup never got to run) is a real, permanent
    disk-space leak if silently excluded forever - so a temp file older than
    staleTempFileAge is treated as orphaned: it's reaped (removed) here rather
    than skipped, so disk space is actually reclaimed instead of just hidden
    from the count.
```
