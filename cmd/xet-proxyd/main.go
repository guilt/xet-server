// Command xet-proxyd runs a caching pull-through proxy in front of the
// real huggingface.co Hub + CAS APIs - not merely a performance cache,
// but an offline-resilience layer: any repo metadata or xorb bytes this
// proxy has successfully served once keep being servable via `hf
// download`/`hf upload` even after huggingface.co becomes completely
// unreachable. See internal/proxycas and internal/proxyhub's package
// doc comments for the full design.
//
// Two ports, mirroring how the real Hub and CAS are actually separate
// services (the same split cmd/xetd itself makes between -addr and
// -hub-addr): -addr serves the CAS-facing proxy (internal/proxycas),
// -hub-addr serves the Hub-facing proxy (internal/proxyhub). Point
// HF_ENDPOINT at the Hub-facing port and the real `hf` CLI works
// end-to-end through this proxy with no other configuration - exactly
// like pointing it at a local xetd, except every request that can't be
// served from cache is relayed to the real huggingface.co instead of
// this being the only copy of the data.
//
// The CAS-facing proxy has no fixed upstream CAS URL of its own (see
// internal/hfclient's package doc comment on why real Xet CAS's base URL
// is discovered per-repo, not configured): it learns the real upstream
// CAS base URL as a side effect of the Hub-facing proxy relaying
// xet-token calls (internal/proxyhub.Server.UpstreamCASBaseURL). This
// means the Hub-facing proxy must actually see live traffic (at least
// once) before the CAS-facing proxy can serve anything it doesn't
// already have cached - running with -hub-addr disabled limits this
// proxy to whatever xorbs a previous run already learned a CAS URL for
// and cached (see -data's snapshot).
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/guilt/xet-server/internal/apidocs"
	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/hfclient"
	"github.com/guilt/xet-server/internal/landingpage"
	"github.com/guilt/xet-server/internal/proxycas"
	"github.com/guilt/xet-server/internal/proxyhub"
	"github.com/guilt/xet-server/internal/ratelimit"
	"github.com/guilt/xet-server/internal/storage/fsstore"
)

func main() {
	// -addr, -hub-addr, and -data intentionally default to the exact same
	// values as cmd/xetd's own flags of the same name - this proxy is a
	// drop-in alternative to xetd for the same two ports, just backed by
	// the real huggingface.co instead of being the only copy of the data.
	addr := flag.String("addr", ":8420", "listen address for the CAS-facing proxy")
	hubAddr := flag.String("hub-addr", "", "listen address for the Hub-facing proxy (empty = disabled)")
	casURL := flag.String("cas-url", "", "externally-reachable CAS base URL to hand out from the Hub-facing proxy's xet-token responses (defaults to http://localhost<addr>)")
	dataDir := flag.String("data", "./xet-data", "directory for the local xorb cache and this proxy's own persisted xorb-size index")
	noCache := flag.Bool("no-cache", false, "disable all local caching on both ports: every request is relayed live to the real upstream with no local storage read/write and no offline fallback. Caching is enabled by default (false) - this flag is a pure-relay escape hatch, not the normal mode, since caching for offline resilience is this program's whole reason to exist")
	cacheTTL := flag.Duration("cache-ttl", -1, "how long a cached Hub metadata response (repo-info, tree, xet-token, resolve) is served without attempting an upstream refresh first. -1 (the default) disables this freshness window: every request still tries the real Hub first, falling back to the last cached value only if that attempt fails. Does not affect the CAS byte cache, which is content-addressed and never goes stale by definition")
	metadataCallTimeout := flag.Duration("metadata-call-timeout", 30*time.Second, "how long a single repo-info/resolve/xet-token upstream call may take before this proxy gives up and falls back to its last cached value (regardless of age) instead of waiting - these are always small, fixed-shape responses that should never legitimately take long. 0 disables this bound entirely, relying only on the calling request's own context and this proxy's HTTP transport-level connect/response-header timeouts. Does not apply to tree listing, which can legitimately span many pages for a large repo")
	upstreamHubURL := flag.String("upstream-hub-url", "", "the real Hub base URL this proxy relays to. Falls back to $HF_URL, then "+hfclient.DefaultHubURL+", if not passed - deliberately not $HF_ENDPOINT, which a downstream `hf` CLI instead sets to point AT this proxy's own -hub-addr")
	snapshotInterval := flag.Duration("snapshot-interval", time.Minute, "how often to persist both proxies' in-memory indices (the CAS-facing proxy's xorb index; the Hub-facing proxy's repo/revision/file/resolve metadata) to -data as a durable checkpoint (0 disables periodic snapshotting; a final snapshot is still taken on graceful shutdown). Upstream credentials and xet access tokens are never written to disk - the token cache and 401-heal index are process-memory only. Without this, a restart while huggingface.co is unreachable would lose everything cached so far and have to relearn it from upstream (or fail outright, if upstream really is unreachable) instead of serving it straight from local storage")
	authToken := flag.String("auth-token", "None", "shared bearer token required to talk to THIS proxy itself (read/write scope per endpoint on both ports) - distinct from the upstream credential, which is always whatever token the caller presents, forwarded to the real Hub/CAS unchanged (pure passthrough; see internal/hfclient's package doc comment). \"None\" (the default) disables local auth enforcement entirely. Falls back to $XET_PROXYD_AUTH_TOKEN if not passed; prefer an environment variable over this flag on any shared/multi-user machine, since flags are visible to other local users via `ps` and end up in shell history")
	rateLimitRPS := flag.Float64("rate-limit-rps", 0, "if > 0, cap sustained requests per source IP to this many requests/second, on BOTH ports and every route (not just uploads, unlike cmd/xetd's own -rate-limit-rps: a read that misses this proxy's cache costs a real outbound call to huggingface.co just as much as a write does). Burst allowance via -rate-limit-burst")
	rateLimitBurst := flag.Float64("rate-limit-burst", 20, "burst allowance for -rate-limit-rps - how many requests a source IP can make immediately before the per-second rate applies")
	flag.Parse()

	if os.Getenv("DEBUG") != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	resolvedUpstreamHubURL := resolveUpstreamHubURL(*upstreamHubURL)
	resolvedAuthToken := resolveAuthToken(*authToken)

	var authenticator auth.Authenticator = auth.NoAuth{}
	if resolvedAuthToken != "" && resolvedAuthToken != "None" {
		authenticator = auth.NewStaticTokenAuth(resolvedAuthToken)
	} else {
		slog.Warn("xet-proxyd starting with no local authentication enforced (-auth-token/$XET_PROXYD_AUTH_TOKEN unset or \"None\"); any client reaching this proxy can read and write. Pass -auth-token <secret> (or set $XET_PROXYD_AUTH_TOKEN) to require a bearer token for access to this proxy itself.")
	}

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	xorbStore, err := fsstore.New(*dataDir + "/xorbs")
	if err != nil {
		log.Fatalf("init xorb store: %v", err)
	}
	casSrv := proxycas.New(xorbStore)
	casSrv.SetAuthenticator(authenticator)
	casSrv.NoCache = *noCache

	// Snapshot filenames deliberately match cmd/xetd's own
	// ("casserver-snapshot.json"/"hubserver-snapshot.json", not
	// "proxycas-..."/"proxyhub-...") - casSrv.Embedded/hubSrv.Embedded
	// are real *casserver.Server/*hubserver.Server instances producing
	// the exact same snapshot format either binary's own Load/Snapshot
	// methods read and write, and this proxy's -data directory is meant
	// to be usable as a plain xetd's -data directory directly (the
	// "hand off to a plain xetd once huggingface.co is gone for good"
	// path this whole program exists for - see the package doc comment).
	// Naming them differently would silently defeat that: a plain xetd
	// pointed at this proxy's -data dir would find no snapshot at all
	// and start with zero cached Hub metadata.
	casSnapshotPath := filepath.Join(*dataDir, "casserver-snapshot.json")
	if err := casSrv.Embedded.LoadSnapshot(casSnapshotPath); err != nil {
		log.Fatalf("load CAS snapshot: %v", err)
	}

	resolvedCASURL := *casURL
	if resolvedCASURL == "" {
		resolvedCASURL = "http://localhost" + *addr
	}
	hubSrv := proxyhub.New(resolvedUpstreamHubURL, resolvedCASURL)
	hubSrv.SetAuthenticator(authenticator)
	hubSrv.NoCache = *noCache
	hubSrv.CacheTTL = *cacheTTL
	hubSrv.MetadataCallTimeout = *metadataCallTimeout

	hubSnapshotPath := filepath.Join(*dataDir, "hubserver-snapshot.json")
	if err := hubSrv.Embedded.LoadSnapshot(hubSnapshotPath); err != nil {
		log.Fatalf("load Hub snapshot: %v", err)
	}

	if *rateLimitRPS > 0 {
		// One Limiter shared across both ports/packages: a client
		// hammering this proxy costs it (and the real huggingface.co
		// behind it) the same regardless of which port the requests land
		// on, so a single source IP should draw down one shared budget,
		// not two independent ones it could double by splitting requests
		// across ports.
		limiter := ratelimit.New(*rateLimitBurst, *rateLimitRPS)
		casSrv.SetRateLimiter(limiter)
		hubSrv.SetRateLimiter(limiter)
		slog.Info("rate limiting enabled on both ports", "requestsPerSecond", *rateLimitRPS, "burst", *rateLimitBurst)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// servers accumulates every http.Server this process starts, so
	// shutdown (below) can gracefully drain all of them, not just the
	// CAS-facing one - a prior version of this binary only ever
	// Shutdown()'d the CAS-facing server, leaving the Hub-facing one (if
	// -hub-addr was set) killed abruptly on exit with no connection
	// draining at all.
	var servers []*http.Server

	var hubHTTPServer *http.Server
	if *hubAddr != "" {
		// API docs on the Hub port too, for the same reason cmd/xetd does
		// it: the spec's default server entry is relative, so loading
		// /api-docs/ from this listener makes Swagger UI's "Try it out"
		// target the Hub API rather than the CAS port it would otherwise
		// (uselessly) aim at across an origin boundary.
		hubMux := http.NewServeMux()
		hubMux.Handle("/api-docs/", http.StripPrefix("/api-docs/", apidocs.Handler()))
		hubMux.Handle("/", withLandingPage(hubSrv, landingpage.ProxyHubHandler()))

		hubHTTPServer = &http.Server{
			Addr:    *hubAddr,
			Handler: logRequests(hubMux),
			// ReadHeaderTimeout/IdleTimeout bound how long a slow or
			// hostile client can hold a connection open before sending
			// a complete request - deliberately no blanket
			// ReadTimeout/WriteTimeout, since relaying a large
			// commit/tree-listing response can legitimately take
			// longer than either. Per-upstream-call bounds are separate
			// (see internal/hfclient's defaultHTTPClient), gating how
			// long THIS server waits on the real Hub, not how long a
			// downstream client may take to send/receive.
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		servers = append(servers, hubHTTPServer)
		go func() {
			slog.Info("xet-proxyd Hub-facing proxy listening", "addr", *hubAddr, "upstreamHubURL", resolvedUpstreamHubURL, "casURL", resolvedCASURL)
			if err := hubHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
	} else {
		slog.Warn("xet-proxyd starting with the Hub-facing proxy disabled (-hub-addr empty); only the CAS-facing proxy on -addr will run, and it can only serve xorbs it already learned an upstream CAS URL for in a previous run. Point HF_ENDPOINT at -hub-addr and pass it here to use `hf` through this proxy end-to-end")
	}

	if *snapshotInterval > 0 {
		go runSnapshotLoop(ctx, *snapshotInterval, []snapshotTarget{
			{"proxycas", casSnapshotPath, casSrv.Embedded},
			{"proxyhub", hubSnapshotPath, hubSrv.Embedded},
		})
	}

	slog.Info("xet-proxyd CAS-facing proxy listening", "addr", *addr, "dataDir", *dataDir, "noCache", *noCache)
	casMux := http.NewServeMux()
	casMux.Handle("/api-docs/", http.StripPrefix("/api-docs/", apidocs.Handler()))
	casMux.Handle("/", withLandingPage(withUpstreamCASClient(hubSrv, casSrv), landingpage.ProxyCASHandler(*addr, *hubAddr)))
	server := &http.Server{
		Addr:              *addr,
		Handler:           logRequests(casMux),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	servers = append(servers, server)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down: taking a final snapshot before exit")
	// shutdownTimeout must exceed the longest single operation an
	// in-flight handler could still legitimately be running when
	// shutdown begins - for this binary, that's a real outbound call to
	// the actual huggingface.co via internal/hfclient, which has no
	// overall request Timeout of its own (only per-phase bounds; see
	// defaultHTTPClient's doc comment), so a large, slow-but-progressing
	// xorb transfer could still be in flight. 60s is generous headroom
	// above hfclient's own 10s per-phase Transport timeouts while still
	// bounding shutdown itself - contrast with cmd/xetd's 10s, which is
	// sufficient there because its handlers only ever touch local
	// storage.
	const shutdownTimeout = 60 * time.Second
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("server did not shut down cleanly within the timeout", "addr", srv.Addr, "error", err)
		}
	}
	if err := casSrv.Embedded.Snapshot(casSnapshotPath); err != nil {
		slog.Error("final CAS snapshot failed", "error", err)
	}
	if err := hubSrv.Embedded.Snapshot(hubSnapshotPath); err != nil {
		slog.Error("final Hub snapshot failed", "error", err)
	}
}

// withLandingPage wraps next so an exact "GET /" request is answered by
// landing instead of being forwarded - every other method and every
// non-root path (including a bare "HEAD /", which http.ServeMux would
// otherwise silently route to a registered "GET /" handler) still goes to
// next unchanged. Identical to cmd/xetd's own withLandingPage, duplicated
// rather than shared since neither binary imports the other and this is
// a handful of lines - see hubserver's real "HEAD /{repo}/resolve/..."
// traffic (proxyhub delegates to it) for why a second http.ServeMux
// specifically must NOT be used here instead.
func withLandingPage(next http.Handler, landing http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			landing(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// withUpstreamCASClient wraps next (the CAS-facing proxy) so every
// request carries a *hfclient.CASClient built from hub's most recently
// learned real upstream CAS base URL (internal/proxyhub.Server.
// UpstreamCASBaseURL - populated as a side effect of the Hub-facing
// proxy relaying xet-token calls; see the package doc comment on why
// there is no other way to learn it). A request arriving before any
// xet-token call has ever been relayed (hub-addr disabled, or a fresh
// process that hasn't seen Hub traffic yet) gets a 503 rather than being
// passed through with no CAS client at all, since proxycas.Server has no
// way to fetch anything from upstream without one.
func withUpstreamCASClient(hub *proxyhub.Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		casURL, ok := hub.UpstreamCASBaseURL()
		if !ok {
			http.Error(w, "upstream CAS URL not yet known: no xet-token request has been relayed through the Hub-facing proxy yet", http.StatusServiceUnavailable)
			return
		}
		ctx := proxycas.WithCASClient(r.Context(), hfclient.NewCASClient(casURL))
		// Also wire in the Hub-facing proxy as a token refresher, so the
		// CAS-facing proxy can transparently heal a 401 the real CAS
		// returns for a client's expired xet access token by minting a
		// fresh one with that same client's credential (see
		// proxycas.fetchCASWithHeal).
		ctx = proxycas.WithTokenRefresher(ctx, hub)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// resolveUpstreamHubURL resolves the real Hub base URL this proxy
// relays to: the -upstream-hub-url flag, then $HF_URL, then
// hfclient.DefaultHubURL. Deliberately not $HF_ENDPOINT - that variable
// is what a downstream `hf` CLI sets to point AT this proxy's own
// -hub-addr, the opposite direction; reusing it here would collide with
// that meaning for anyone who has both set.
func resolveUpstreamHubURL(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if v := os.Getenv("HF_URL"); v != "" {
		return v
	}
	return hfclient.DefaultHubURL
}

// resolveAuthToken resolves this proxy's own local-access shared bearer
// token from the -auth-token flag, falling back to
// $XET_PROXYD_AUTH_TOKEN - deliberately not $HF_TOKEN (unlike cmd/xetd's
// resolveAuthToken): $HF_TOKEN is the credential a caller presents for
// this proxy to forward upstream unchanged (pure passthrough), a
// completely independent concern from who may talk to this proxy
// itself; falling back to it here would conflate the two.
func resolveAuthToken(flagValue string) string {
	return auth.ResolveToken(flagValue, "XET_PROXYD_AUTH_TOKEN")
}

// snapshotter is implemented by both casserver.Server.Snapshot and
// hubserver.Server.Snapshot - proxycas/proxyhub have no snapshot format
// of their own (each embeds a real casserver.Server/hubserver.Server as
// its serving engine; see their package doc comments), so this binary
// snapshots casSrv.Embedded/hubSrv.Embedded directly.
type snapshotter interface {
	Snapshot(path string) error
}

// snapshotTarget pairs a Snapshot-capable server with the file path its
// snapshots are written to and a name for logging - mirrors cmd/xetd's
// own snapshotTarget.
type snapshotTarget struct {
	name string
	path string
	snapshotter
}

// runSnapshotLoop periodically snapshots every target until ctx is
// canceled (at which point main takes one last snapshot itself before
// exiting). A failed periodic snapshot is logged but never aborts the
// loop or the process - mirrors cmd/xetd's own runSnapshotLoop.
func runSnapshotLoop(ctx context.Context, interval time.Duration, targets []snapshotTarget) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, target := range targets {
				if err := target.Snapshot(target.path); err != nil {
					slog.Error("periodic snapshot failed", "server", target.name, "error", err)
				}
			}
		}
	}
}

// logRequests wraps a handler to log every request at debug level -
// identical to cmd/xetd's own logRequests, duplicated rather than
// shared since neither binary imports the other and this is a handful
// of lines.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		slog.Debug("request received", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.Debug("request completed", "method", r.Method, "path", r.URL.Path, "status", sw.status, "duration", time.Since(start))
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
