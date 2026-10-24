package proxyhub

// cache.go: the freshness-tracking primitive every read endpoint in
// this package uses. Unlike the old standalone proxyhub, this package
// no longer caches VALUES itself - those live in Embedded (a real
// *hubserver.Server) - it only needs to remember WHEN each key was last
// successfully refreshed from upstream, to implement -cache-ttl's
// freshness window. See the package doc comment for the exact
// stale-fallback policy.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

// cacheKey joins parts into one map key using a separator ("\x00") that
// cannot appear in any of repoType/repoID/revision/filename, unlike "/"
// which repoID itself already contains.
func cacheKey(parts ...string) string {
	return strings.Join(parts, "\x00")
}

// credentialFingerprint identifies the caller's credential without storing
// it: a SHA-256 of the exact Authorization header the request carried. The
// empty header (anonymous) gets its own stable value. Cache entries whose
// value depends on authorization include this in their key, so one caller's
// upstream token or private-repo metadata can never be served to another.
func credentialFingerprint(r *http.Request) string {
	sum := sha256.Sum256([]byte(r.Header.Get("Authorization")))
	return hex.EncodeToString(sum[:])
}

// ttlCache[V] is reused for two different purposes in this package:
//   - V = struct{}: repoInfoFreshness/treeFreshness/resolveFreshness only
//     need a timestamp per key (the data itself lives in Embedded).
//   - V = *hfclient.XetToken / string: xetTokenCache/casURLCache still
//     need to hold an actual value, since xet-token responses are never
//     ingested into Embedded (hubserver's own token minting is fake - see
//     the package doc comment) and the CAS URL has no home in Embedded at
//     all.
type ttlCache[V any] struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry[V]
	now     func() time.Time
}

type cacheEntry[V any] struct {
	value    V
	storedAt time.Time
}

func newTTLCache[V any]() *ttlCache[V] {
	return &ttlCache[V]{entries: make(map[string]cacheEntry[V]), now: time.Now}
}

// Get reports whether an entry exists at all under key (present, at any
// age) and, separately, whether it's within ttl of now (fresh). ttl < 0
// means "never fresh" - every read must attempt an upstream refresh
// first, falling back to this same entry only if that attempt fails.
func (c *ttlCache[V]) Get(key string, ttl time.Duration) (value V, present, fresh bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok {
		return value, false, false
	}
	fresh = ttl >= 0 && c.now().Sub(e.storedAt) <= ttl
	return e.value, true, fresh
}

func (c *ttlCache[V]) Set(key string, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = cacheEntry[V]{value: value, storedAt: c.now()}
}

// Fresh reports whether key was marked fresh (via MarkFresh) within
// ttl - the struct{}-valued freshness caches' whole API surface, since
// they never need to store or retrieve any actual value.
func (c *ttlCache[V]) Fresh(key string, ttl time.Duration) bool {
	_, present, fresh := c.Get(key, ttl)
	return present && fresh
}

// MarkFresh records key as freshly refreshed right now.
func (c *ttlCache[V]) MarkFresh(key string) {
	var zero V
	c.Set(key, zero)
}
