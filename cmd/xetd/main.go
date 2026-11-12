// Command xetd runs local HTTP servers that speak the real Xet CAS
// protocol (internal/casserver, mounted at /v1, /v2 - wire-compatible with
// hf_xet/xet-core) alongside a simpler demo chunk/dedup API
// (internal/api, mounted at /upload, /files) for quick manual testing, and
// optionally a Hub API shim (internal/hubserver) on a separate port so the
// real `hf upload`/`hf download` CLI commands work end-to-end via
// HF_ENDPOINT - mirroring how huggingface.co's Hub and CAS are actually
// separate services. An interactive Swagger UI documenting every endpoint
// above is served at /api-docs, fully offline (see internal/apidocs).
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
	"sync"
	"syscall"
	"time"

	"github.com/guilt/xet-server/internal/api"
	"github.com/guilt/xet-server/internal/apidocs"
	"github.com/guilt/xet-server/internal/auth"
	"github.com/guilt/xet-server/internal/casserver"
	"github.com/guilt/xet-server/internal/eviction"
	"github.com/guilt/xet-server/internal/hubserver"
	"github.com/guilt/xet-server/internal/landingpage"
	"github.com/guilt/xet-server/internal/ratelimit"
	"github.com/guilt/xet-server/internal/routing"
	"github.com/guilt/xet-server/internal/storage"
	"github.com/guilt/xet-server/internal/storage/fsstore"
)

func main() {
	// `xetd gc ...` is the garbage collector's client (gc.go); anything
	// else runs the server.
	if len(os.Args) > 1 && os.Args[1] == "gc" {
		runGC(os.Args[2:])
		return
	}

	addr := flag.String("addr", ":8420", "listen address for the CAS + Xet Data API server")
	hubAddr := flag.String("hub-addr", "", "listen address for the Hub API shim (empty = disabled)")
	casURL := flag.String("cas-url", "", "externally-reachable CAS base URL to hand out from the Hub shim (defaults to http://localhost<addr>)")
	dataDir := flag.String("data", "./xet-data", "directory for chunks, xorbs, and manifests")
	maxStorageBytes := flag.Int64("max-storage-bytes", 0, "if > 0, periodically evict least-recently-accessed xorbs once total xorb storage exceeds this many bytes. This is cache behavior: it deletes xorbs that files still reference. For a server that is the only copy of its data, leave it off and reclaim space with `xetd gc` (see -gc-grace)")
	gcGrace := flag.Duration("gc-grace", casserver.DefaultGCGrace, "default grace period for POST /v1/gc (`xetd gc`): a xorb uploaded, fetched, or advertised in a dedup answer more recently than this is never deleted, whatever the keep set says. The default is the 3 weeks a xet client keeps its own shards in its cache (and dedups from them without asking), plus a day; a client whose cache outlives a shorter grace can push a file that references a deleted xorb. A request may override it per run")
	evictionInterval := flag.Duration("eviction-interval", 5*time.Minute, "how often to check storage usage against -max-storage-bytes")
	rateLimitRPS := flag.Float64("rate-limit-rps", 0, "if > 0, cap sustained xorb/shard uploads per source IP to this many requests/second (burst allowance via -rate-limit-burst)")
	rateLimitBurst := flag.Float64("rate-limit-burst", 20, "burst allowance for -rate-limit-rps - how many upload requests a source IP can make immediately before the per-second rate applies")
	verifyDedup := flag.Bool("verify-dedup", false, "on every dedup hit, byte-compare the incoming upload against the stored blob instead of trusting the content hash alone (doubles I/O per dedup hit; off by default)")
	snapshotInterval := flag.Duration("snapshot-interval", time.Minute, "how often to persist in-memory reconstruction/repo indices to -data as a durable checkpoint (0 disables periodic snapshotting; a final snapshot is still taken on graceful shutdown)")
	tokenTTL := flag.Duration("token-ttl", time.Hour, "lifetime of the CAS access tokens the Hub shim mints for hf_xet, git-xet, and git-lfs download links; clients refresh through the xet-{read,write}-token routes when one nears expiry")
	authToken := flag.String("auth-token", "None", "shared bearer token required on every request (CAS: read/write scope per endpoint; Hub: same). \"None\" (the default) disables auth enforcement entirely, matching this server's behavior prior to v0.8.0 - implement auth.Authenticator for anything beyond a single shared secret. Falls back to $XETD_AUTH_TOKEN, then $HF_TOKEN, if not passed; prefer an environment variable over this flag on any shared/multi-user machine, since flags are visible to other local users via `ps` and end up in shell history")
	syncFolder := flag.Bool("sync-folder", false, "treat -data as a folder a sync tool (Dropbox, Syncthing, a NAS mount) shares with other xetd replicas: every authoritative file is write-once and content-named, no snapshot is written or read (the index is rebuilt from the shard files at startup), git-lfs locks are claim files with a deterministic election, and the shard directory is rescanned for other replicas' uploads; see docs/GIT_LFS.md")
	rescanInterval := flag.Duration("rescan-interval", 10*time.Second, "with -sync-folder, how often to look for shards other replicas wrote (0: only at startup and when a lookup misses)")
	flag.Parse()

	if os.Getenv("DEBUG") != "" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	resolvedAuthToken := resolveAuthToken(*authToken)

	// With a shared secret configured, both servers use SignedTokenAuth:
	// the CAS then accepts the scoped, expiring tokens the Hub shim
	// mints (and the secret itself, as Bearer or as a git-lfs Basic
	// password), so hf_xet, git-xet, and git-lfs all authenticate at the
	// CAS with a token that never exposes the secret to the client.
	var authenticator auth.Authenticator = auth.NoAuth{}
	var minter auth.TokenMinter
	if resolvedAuthToken != "" && resolvedAuthToken != "None" {
		signed := auth.NewSignedTokenAuth(resolvedAuthToken)
		authenticator = signed
		minter = signed
	} else {
		slog.Warn("xetd starting with no authentication enforced (-auth-token/$XETD_AUTH_TOKEN/$HF_TOKEN unset or \"None\"); any client can read and write. Pass -auth-token <secret> (or set $XETD_AUTH_TOKEN/$HF_TOKEN) to require a bearer token, or implement auth.Authenticator for anything beyond a single shared secret.")
	}

	demoSrv, err := api.New(*dataDir)
	if err != nil {
		log.Fatalf("init demo api: %v", err)
	}
	demoSrv.SetAuthenticator(authenticator)

	xorbStore, err := fsstore.New(*dataDir + "/xorbs")
	if err != nil {
		log.Fatalf("init xorb store: %v", err)
	}
	var casXorbStore storage.Store = xorbStore
	if *verifyDedup {
		casXorbStore = storage.NewVerifyingStore(xorbStore)
		slog.Info("dedup verification enabled: every dedup hit will be byte-compared against the stored blob")
	}
	casSrv := casserver.New(casXorbStore)
	casSrv.SetAuthenticator(authenticator)
	if minter != nil {
		// hf_xet fetches the xorb URLs in a reconstruction response with
		// no Authorization header, so with auth on they carry their own
		// read token, like the presigned URLs the real CAS hands out.
		casSrv.SetFetchURLSigner(minter, *tokenTTL)
	}

	// Shard bodies are persisted as content-named files (a durable,
	// append-only record the snapshot below is merely a cache of), and
	// any shard the snapshot does not cover is re-indexed from them.
	if err := casSrv.SetShardDir(filepath.Join(*dataDir, "shards")); err != nil {
		log.Fatalf("init shard dir: %v", err)
	}
	casSnapshotPath := filepath.Join(*dataDir, "casserver-snapshot.json")
	if !*syncFolder {
		if err := casSrv.LoadSnapshot(casSnapshotPath); err != nil {
			log.Fatalf("load CAS snapshot: %v", err)
		}
	}
	if added, err := casSrv.ScanShards(context.Background()); err != nil {
		log.Fatalf("scan shard dir: %v", err)
	} else if added > 0 {
		slog.Info("indexed shards not covered by the snapshot", "added", added)
	}
	// The snapshot is only an index; correct any stale xorb lengths against
	// the content-addressed blobs on disk before serving.
	casSrv.ReconcileXorbLengths(context.Background())
	if *syncFolder {
		slog.Info("synced-folder mode: no snapshots; state is derived from the files in -data", "dataDir", *dataDir, "rescanInterval", *rescanInterval)
		if *maxStorageBytes > 0 {
			log.Fatalf("-max-storage-bytes cannot be combined with -sync-folder: eviction deletes files other replicas still reference")
		}
	}

	if *maxStorageBytes > 0 {
		evictionStore, ok := casXorbStore.(eviction.Store)
		if !ok {
			log.Fatalf("-max-storage-bytes requires a storage backend supporting Delete+TotalBytes; got %T", casXorbStore)
		}
		sweeper := eviction.New(evictionStore, casSrv, *maxStorageBytes, *evictionInterval)
		casSrv.SetEvictionStats(sweeper.Stats)
		go sweeper.Run(context.Background())
		slog.Info("eviction sweep enabled", "budgetBytes", *maxStorageBytes, "interval", *evictionInterval)
	}

	if *rateLimitRPS > 0 {
		casSrv.SetUploadRateLimiter(ratelimit.New(*rateLimitBurst, *rateLimitRPS))
		slog.Info("upload rate limiting enabled", "requestsPerSecond", *rateLimitRPS, "burst", *rateLimitBurst)
	}

	// Garbage collection is wired here and never in casserver.Server's
	// own routes, so the Server that xet-proxyd embeds (a cache, where
	// LRU eviction is the right tool) cannot get it. The Hub shim's
	// registry (if enabled) is added to every keep set below.
	gcConfig := casserver.GCHandlerConfig{DefaultGrace: *gcGrace}
	if *syncFolder {
		gcConfig.Disabled = "this xetd serves a synced folder (-sync-folder), where other replicas may still reference what one replica deletes"
	} else {
		gcConfig.AfterCollect = func() error { return casSrv.Snapshot(casSnapshotPath) }
	}

	mux := http.NewServeMux()
	routing.Apply(mux, []routing.Route{
		routing.Mount("", "/api-docs/", http.StripPrefix("/api-docs/", apidocs.Handler())),
		routing.Mount("POST", casserver.GCPath, gcHandlerFor(casSrv, &gcConfig)),
		// demoSrv's own literal /v1 sub-paths (api.UploadPath,
		// api.FilesPrefix, api.StatsPath) are registered on this shared
		// mux ahead of casSrv's api.V1+"/" wildcard - Go's http.ServeMux
		// always prefers the more specific pattern regardless of
		// registration order, so these never collide with casSrv's own
		// /v1 paths (xorbs, shards, reconstructions, chunks, telemetry,
		// storage-stats). See internal/api's exported path constants for
		// the full list this covers.
		routing.Mount("", api.UploadPath, demoSrv),
		routing.Mount("", api.FilesPrefix, demoSrv),
		routing.Mount("", api.StatsPath, demoSrv),
		routing.Mount("", casserver.V1+"/", casSrv),
		routing.Mount("", casserver.V2+"/", casSrv),
		// Newer xet-core clients upload shards to an unversioned path;
		// see casserver.ShardsPathUnversioned.
		routing.Mount("POST", casserver.ShardsPathUnversioned, casSrv),
		routing.Mount("", "/", http.HandlerFunc(landingpage.CASHandler(*addr, *hubAddr))),
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// snapshotTargets accumulates every Snapshot-capable server this
	// process started (CAS, and Hub if enabled), so the shutdown-time
	// final snapshot (below) and the periodic snapshot loop cover
	// whatever is actually running rather than hardcoding just one.
	var snapshotTargets []snapshotTarget
	if !*syncFolder {
		snapshotTargets = append(snapshotTargets, snapshotTarget{"casserver", casSnapshotPath, casSrv})
	}

	// servers accumulates every http.Server this process starts, so
	// shutdown (below) can gracefully drain all of them, not just the
	// CAS-facing one - a prior version of this binary only ever
	// Shutdown()'d the CAS-facing server, leaving the Hub shim (if
	// -hub-addr was set) killed abruptly on exit with no connection
	// draining at all.
	var servers []*http.Server

	var hubSrv *hubserver.Server
	if *hubAddr != "" {
		resolvedCASURL := *casURL
		if resolvedCASURL == "" {
			resolvedCASURL = "http://localhost" + *addr
		}
		hubSrv = hubserver.New(resolvedCASURL, casSrv)
		hubSrv.SetAuthenticator(authenticator)
		hubSrv.SetTokenMinter(minter)
		hubSrv.SetTokenTTL(*tokenTTL)
		// Files committed through the Hub shim have no git repo to list
		// them from; the registry is what says they are still wanted.
		gcConfig.ExtraKeep = hubSrv.FileSHA256s

		hubSnapshotPath := filepath.Join(*dataDir, "hubserver-snapshot.json")
		if *syncFolder {
			// Locks become claim files in the folder; the Hub's own
			// repo/revision registry (used by hf upload/download, not by
			// git-lfs) stays in memory for this process only.
			if err := hubSrv.SetLockDir(filepath.Join(*dataDir, "locks")); err != nil {
				log.Fatalf("init lock dir: %v", err)
			}
		} else {
			if err := hubSrv.LoadSnapshot(hubSnapshotPath); err != nil {
				log.Fatalf("load Hub snapshot: %v", err)
			}
			snapshotTargets = append(snapshotTargets, snapshotTarget{"hubserver", hubSnapshotPath, hubSrv})
		}

		// Serve the API docs on the Hub port as well as the CAS port. The
		// spec's default server entry is a RELATIVE url ("/"), so it
		// resolves against whichever origin the docs were loaded from -
		// which means opening /api-docs/ here makes Swagger UI's "Try it
		// out" target this Hub listener, and Hub endpoints become
		// same-origin and actually callable. Served only from the CAS
		// port, they never could be: a cross-port call is cross-origin,
		// and this server deliberately sends no CORS headers (a
		// permissive policy would let any site the operator visits drive
		// their local server). Same embedded spec either way - it
		// documents both APIs.
		hubMux := http.NewServeMux()
		hubMux.Handle("/api-docs/", http.StripPrefix("/api-docs/", apidocs.Handler()))
		hubMux.Handle("/", withLandingPage(hubSrv, landingpage.HubHandler()))

		hubHTTPServer := &http.Server{
			Addr:              *hubAddr,
			Handler:           logRequests(hubMux),
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		servers = append(servers, hubHTTPServer)
		go func() {
			slog.Info("xetd Hub API shim listening", "addr", *hubAddr, "casBaseURL", resolvedCASURL)
			if err := hubHTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatal(err)
			}
		}()
	}

	if *snapshotInterval > 0 && len(snapshotTargets) > 0 {
		go runSnapshotLoop(ctx, *snapshotInterval, snapshotTargets)
	}
	if *syncFolder && *rescanInterval > 0 {
		go casSrv.RunRescanLoop(ctx, *rescanInterval)
	}

	slog.Info("xetd listening", "addr", *addr, "dataDir", *dataDir, "apiDocsPath", "/api-docs/")
	server := &http.Server{
		Addr:    *addr,
		Handler: logRequests(mux),
		// ReadHeaderTimeout/IdleTimeout bound how long a slow or hostile
		// client can hold a connection open before sending a complete
		// request (Slowloris-class resource exhaustion) - deliberately
		// no blanket ReadTimeout/WriteTimeout, since a legitimate xorb
		// upload/download body can take longer than either without
		// being unhealthy.
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
	slog.Info("shutting down")
	// 10s is sufficient here (unlike cmd/xet-proxyd's 60s): every handler
	// in this binary only ever touches local storage, never a slow real
	// upstream with no overall request Timeout of its own.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdownCtx); err != nil {
			slog.Warn("server did not shut down cleanly within the timeout", "addr", srv.Addr, "error", err)
		}
	}
	for _, target := range snapshotTargets {
		if err := target.snapshotter.Snapshot(target.path); err != nil {
			slog.Error("final snapshot failed", "server", target.name, "error", err)
		}
	}
}

// gcHandlerFor builds the GC handler lazily, on the first request, so
// the config can still gain the Hub registry hook after the route table
// is assembled (the Hub shim is constructed later in main than the CAS
// mux).
func gcHandlerFor(casSrv *casserver.Server, cfg *casserver.GCHandlerConfig) http.Handler {
	var once sync.Once
	var h http.Handler
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { h = casSrv.GCHandler(*cfg) })
		h.ServeHTTP(w, r)
	})
}

// withLandingPage wraps next so an exact "GET /" request is answered by
// landing instead of being forwarded - every other method and every
// non-root path (including a bare "HEAD /", which http.ServeMux would
// otherwise silently route to a registered "GET /" handler) still goes to
// next unchanged. Used instead of a second http.ServeMux specifically to
// avoid that HEAD-falls-back-to-GET behavior: hubserver's real traffic
// (e.g. "HEAD /{repo}/resolve/{revision}/{filename}") must never be
// intercepted by the landing page.
func withLandingPage(next http.Handler, landing http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			landing(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// resolveAuthToken resolves this server's shared bearer token from the
// -auth-token flag, falling back to $XETD_AUTH_TOKEN, then $HF_TOKEN (the
// same variable the real `hf` CLI reads) - see auth.ResolveToken for the
// precedence rule. The $HF_TOKEN fallback lets a local xetd act as a
// drop-in replacement for the real huggingface.co Xet backend using a
// token a user already has exported for the real `hf` CLI, with no
// separate secret to configure - and, in a future relay/proxy in front of
// the real backend, is the same primitive that would resolve the upstream
// credential to forward a caller's token with.
func resolveAuthToken(flagValue string) string {
	return auth.ResolveToken(flagValue, "XETD_AUTH_TOKEN", "HF_TOKEN")
}

// snapshotter is implemented by both casserver.Server and
// hubserver.Server's Snapshot method.
type snapshotter interface {
	Snapshot(path string) error
}

// snapshotTarget pairs a Snapshot-capable server with the file path its
// snapshots are written to and a name for logging.
type snapshotTarget struct {
	name string
	path string
	snapshotter
}

// runSnapshotLoop periodically snapshots every target until ctx is
// canceled (at which point main takes one last snapshot itself before
// exiting - see the <-ctx.Done() block above). Each target's Snapshot
// error is logged but never aborts the loop or the process: a failed
// periodic snapshot just means this checkpoint didn't advance, not that
// the server is unhealthy.
func runSnapshotLoop(ctx context.Context, interval time.Duration, targets []snapshotTarget) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var wg sync.WaitGroup
			for _, target := range targets {
				wg.Add(1)
				go func(target snapshotTarget) {
					defer wg.Done()
					if err := target.Snapshot(target.path); err != nil {
						slog.Error("periodic snapshot failed", "server", target.name, "error", err)
					}
				}(target)
			}
			wg.Wait()
		}
	}
}

// logRequests wraps a handler to log every request at debug level: the
// request line as soon as it's received (before any handler code runs, so
// a hung/slow handler still shows up as "received" in the log), and the
// response status/duration once it completes. Only active when DEBUG is
// set (see slog.SetLogLoggerLevel above) - slog.Debug is a no-op call
// otherwise, so this has no cost in normal operation.
func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		slog.Debug("request received", "method", r.Method, "path", r.URL.Path, "remote", r.RemoteAddr)
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		slog.Debug("request completed", "method", r.Method, "path", r.URL.Path, "status", sw.status, "duration", time.Since(start))
	})
}

// statusWriter captures the status code passed to WriteHeader so
// logRequests can log it after the handler runs; http.ResponseWriter
// itself exposes no way to read back what a handler wrote.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
