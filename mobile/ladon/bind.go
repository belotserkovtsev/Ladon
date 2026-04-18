// Package ladon is the gomobile-bound surface of the ladon engine for iOS
// Network Extensions. Path mirrors cmd/ladon — mobile/ladon hosts the
// mobile-platform "binary" (an .xcframework) of the same engine, and the
// package name drives the generated Swift module: Swift callers see
// `import Ladon` and LadonNew/LadonEngine, not Ios/IosEngine.
//
// Scope is intentionally narrow — four methods — because gomobile marshals
// every call across a Swift↔ObjC↔Go bridge and idiomatic Go APIs (channels,
// variadic, maps, generics) don't cross cleanly. Everything that isn't a
// DNS event flows through file-based IPC in the host app's app-group
// container: the engine publishes hot-snapshot.json, the Swift side watches
// it and rebuilds its routing Set<String> on each change.
//
// Usage from Swift (after `import Ladon`):
//
//	let cfg = "{\"db_path\":\"...\",\"snapshot_path\":\"...\"}"
//	let eng = try LadonNew(cfg)
//	try eng.start()
//	// on each NE DNS flow:
//	eng.onDNSQuery("reddit.com", resolvedIPsJSON: "[\"151.101.65.140\"]")
//	// on NE shutdown:
//	try eng.shutdown()
//
// The engine is safe to call concurrently after Start; OnDNSQuery is
// fire-and-forget and returns in sub-millisecond time regardless of probe
// activity.
package ladon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/belotserkovtsev/ladon/internal/engine"
	"github.com/belotserkovtsev/ladon/internal/prober"
	"github.com/belotserkovtsev/ladon/internal/storage"

	// Anchor import: gobind (invoked by gomobile bind) resolves
	// golang.org/x/mobile/bind from the current module's dep graph.
	// Nothing in this package references the bind package directly; without
	// this blank import `go mod tidy` drops it, gobind fails with
	// "unable to import bind: no Go package in golang.org/x/mobile/bind".
	_ "golang.org/x/mobile/bind"
)

// Config is the JSON shape consumed by New. All durations are expressed in
// integer units (seconds, minutes, hours) rather than Go's time.Duration
// string format — JSON is the contract with Swift, and Swift has no native
// Duration concept, so integer knobs are the least surprising lingua franca.
// Omitted fields fall through to engine.Defaults.
type Config struct {
	// DBPath is the absolute path to the SQLite database. Typically lives
	// under the NE's app-group shared container so the container app can
	// read stats out-of-band.
	DBPath string `json:"db_path"`

	// SnapshotPath is where PublishSnapshotJSON writes the hot/cache/manual
	// JSON artifact. The Swift side watches this file and reloads its
	// in-memory IP set on each write.
	SnapshotPath string `json:"snapshot_path"`

	// Optional tuning knobs — leave at 0 for defaults.
	ProbeTimeoutMS         int `json:"probe_timeout_ms,omitempty"`
	ProbeCooldownSec       int `json:"probe_cooldown_sec,omitempty"`
	InlineProbeConcurrency int `json:"inline_probe_concurrency,omitempty"`
	HotTTLSec              int `json:"hot_ttl_sec,omitempty"`
	DNSFreshnessSec        int `json:"dns_freshness_sec,omitempty"`
	PublishIntervalSec     int `json:"publish_interval_sec,omitempty"`
	ScorerIntervalSec      int `json:"scorer_interval_sec,omitempty"`
	ScorerWindowSec        int `json:"scorer_window_sec,omitempty"`
	ScorerFailThreshold    int `json:"scorer_fail_threshold,omitempty"`

	// RemoteProbeURL enables the optional exit-compare validator. Leave
	// empty to run with local probe only (the current production default
	// on jupiter/ягода).
	RemoteProbeURL        string `json:"remote_probe_url,omitempty"`
	RemoteProbeTimeoutMS  int    `json:"remote_probe_timeout_ms,omitempty"`
	RemoteProbeAuthHeader string `json:"remote_probe_auth_header,omitempty"`
	RemoteProbeAuthValue  string `json:"remote_probe_auth_value,omitempty"`
}

// Engine is the gomobile-exported handle. Opaque to Swift — all operations
// go through the exported methods.
type Engine struct {
	mu      sync.Mutex
	cfg     engine.Config
	store   *storage.Store
	rt      *engine.Runtime
	cancel  context.CancelFunc
	running bool
	closed  bool
}

// New parses the JSON config, opens the SQLite store, and returns a ready-
// but-not-started Engine. Call Start to spawn background goroutines.
//
// Errors surface as Swift throws via gomobile's (T, error) convention.
func New(configJSON string) (*Engine, error) {
	defer recoverPanic("New")

	var raw Config
	if err := json.Unmarshal([]byte(configJSON), &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if raw.DBPath == "" {
		return nil, fmt.Errorf("config: db_path is required")
	}

	store, err := storage.Open(raw.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	if err := store.Init(context.Background()); err != nil {
		store.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	cfg := engine.Defaults("")
	// iOS explicitly disables all Linux-only stages. Empty strings are the
	// guard signal honoured by engine.Start — no tailer, no ipset syncer,
	// no dnsmasq.conf generation.
	cfg.LogPath = ""
	cfg.IpsetName = ""
	cfg.ManualIpsetName = ""
	cfg.PublishPath = ""
	cfg.SnapshotPath = raw.SnapshotPath
	applyOverrides(&cfg, &raw)

	return &Engine{cfg: cfg, store: store}, nil
}

// Start spawns the engine's background goroutines. Idempotent — calling
// twice returns nil without double-starting.
func (e *Engine) Start() error {
	defer recoverPanic("Start")

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.running {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	rt, err := engine.Start(ctx, e.store, e.cfg)
	if err != nil {
		cancel()
		return fmt.Errorf("engine start: %w", err)
	}
	e.rt = rt
	e.cancel = cancel
	e.running = true
	return nil
}

// Shutdown cancels the engine context (if running) and closes the store.
// Idempotent — safe to call before Start (closes an already-open DB
// handle), multiple times (becomes a no-op after the first success).
func (e *Engine) Shutdown() error {
	defer recoverPanic("Shutdown")

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	if e.cancel != nil {
		e.cancel()
		e.cancel = nil
	}
	e.running = false
	e.closed = true
	// Give goroutines a moment to unwind so writes land before Close.
	// storage.Close blocks until in-flight queries drain, but the scorer
	// and probe-worker tick on cooldown timers — a short settle avoids
	// noisy "context canceled" log spam from mid-query cancellations.
	time.Sleep(50 * time.Millisecond)
	if err := e.store.Close(); err != nil {
		return fmt.Errorf("close store: %w", err)
	}
	return nil
}

// OnDNSQuery is the hot-path entry from the Swift Network Extension. Called
// once per resolved DNS query: domain is the queried name (lowercase, no
// trailing dot); resolvedIPsJSON is a JSON array of IPv4 strings as
// returned by the upstream resolver.
//
// Fire-and-forget — returns in sub-millisecond time. Ingestion and probe
// scheduling happen asynchronously; probe results surface via updates to
// the snapshot file that the NE already watches.
//
// Errors (bad JSON, closed engine) are logged, not returned — Swift's hot
// path shouldn't branch on engine state.
func (e *Engine) OnDNSQuery(domain, resolvedIPsJSON string) {
	defer recoverPanic("OnDNSQuery")

	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	rt := e.rt
	e.mu.Unlock()

	var ips []string
	if resolvedIPsJSON != "" {
		if err := json.Unmarshal([]byte(resolvedIPsJSON), &ips); err != nil {
			log.Printf("ios.OnDNSQuery %q: bad ips JSON: %v", domain, err)
			// fall through with empty ips — the domain still counts as observed
		}
	}

	// Off the Swift caller's goroutine: OnDNSEvent's work is bounded but
	// its SQLite writes can compete with the probe-worker on the write
	// pool's single slot. Swift's NE flow handler shouldn't pay that
	// latency — dispatch into the engine's own goroutine pool.
	go func() {
		defer recoverPanic("OnDNSEvent")
		// peer is left empty on iOS — the device has a single logical
		// client (itself), and IgnorePeer filtering is a gateway concern.
		if err := rt.OnDNSEvent(context.Background(), domain, "", ips); err != nil {
			log.Printf("ios.OnDNSEvent %q: %v", domain, err)
		}
	}()
}

// applyOverrides copies non-zero knobs from raw into cfg. Each field
// guards on >0 so callers can leave unused knobs at 0 and inherit the
// engine defaults.
func applyOverrides(cfg *engine.Config, raw *Config) {
	if raw.ProbeTimeoutMS > 0 {
		cfg.ProbeTimeout = time.Duration(raw.ProbeTimeoutMS) * time.Millisecond
	}
	if raw.ProbeCooldownSec > 0 {
		cfg.ProbeCooldown = time.Duration(raw.ProbeCooldownSec) * time.Second
	}
	if raw.InlineProbeConcurrency > 0 {
		cfg.InlineProbeConcurrency = raw.InlineProbeConcurrency
	}
	if raw.HotTTLSec > 0 {
		cfg.HotTTL = time.Duration(raw.HotTTLSec) * time.Second
	}
	if raw.DNSFreshnessSec > 0 {
		cfg.DNSFreshness = time.Duration(raw.DNSFreshnessSec) * time.Second
	}
	if raw.PublishIntervalSec > 0 {
		cfg.PublishInterval = time.Duration(raw.PublishIntervalSec) * time.Second
	}
	if raw.ScorerIntervalSec > 0 {
		cfg.Scorer.Interval = time.Duration(raw.ScorerIntervalSec) * time.Second
	}
	if raw.ScorerWindowSec > 0 {
		cfg.Scorer.Window = time.Duration(raw.ScorerWindowSec) * time.Second
	}
	if raw.ScorerFailThreshold > 0 {
		cfg.Scorer.FailThreshold = raw.ScorerFailThreshold
	}
	if raw.RemoteProbeURL != "" {
		timeout := time.Duration(raw.RemoteProbeTimeoutMS) * time.Millisecond
		cfg.RemoteProber = prober.NewRemote(
			raw.RemoteProbeURL,
			raw.RemoteProbeAuthHeader,
			raw.RemoteProbeAuthValue,
			timeout,
		)
	}
}

// recoverPanic stops a panicking goroutine from tearing down the host NE
// process. gomobile propagates panics poorly across the ObjC boundary —
// trap them here, log, and let Swift keep running.
func recoverPanic(where string) {
	if r := recover(); r != nil {
		log.Printf("ios.%s: panic: %v", where, r)
	}
}
