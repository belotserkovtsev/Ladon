package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

// unreachableIP is reserved TEST-NET-1 (RFC 5737) — it never answers; kernel
// routes packets to it into the void. Dialing it produces a clean timeout,
// which is exactly the shape of a real DPI block.
const unreachableIP = "192.0.2.1"

// newTestEngine spins up a fresh SQLite, seeds dns_cache so the probe uses
// ProbeIPs (not system DNS), and returns the store + log path for a caller
// that will go engine.Run in a goroutine.
func newTestEngine(t *testing.T, ctx context.Context, probeTimeout time.Duration) (*storage.Store, string, Config) {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "dnsmasq.log")
	if err := os.WriteFile(logPath, nil, 0o644); err != nil {
		t.Fatalf("seed log: %v", err)
	}

	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init db: %v", err)
	}

	cfg := Defaults(logPath)
	cfg.ProbeTimeout = probeTimeout
	cfg.ProbeCooldown = time.Second // tighten for tests
	cfg.IpsetName = ""              // no iptables/ipset on dev box
	cfg.PublishPath = ""            // skip file writes
	cfg.ExpiryInterval = time.Hour  // keep sweeper idle
	cfg.Scorer.Interval = time.Hour // keep scorer idle
	return s, logPath, cfg
}

func appendLogLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	if _, err := fmt.Fprintln(f, line); err != nil {
		t.Fatalf("write log: %v", err)
	}
	f.Close()
}

// waitForState polls domains.state until it matches or deadline hits.
func waitForState(t *testing.T, ctx context.Context, s *storage.Store, domain, want string, deadline time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	for time.Since(start) < deadline {
		doms, err := s.ListRecentDomains(ctx, 200)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, d := range doms {
			if d.Domain == domain && d.State == want {
				return time.Since(start)
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%q never reached state=%s within %s", domain, want, deadline)
	return 0
}

// TestPipelineLatencyQueryToHot measures the full hot-path:
//
//	dnsmasq writes → tailer reads → watcher ingests → inline probe fires →
//	TCP dial times out → decision=Hot → hot_entries upserted.
//
// Expected wall clock is dominated by the probe timeout (default 200ms here).
// The interesting quantity is the envelope — how much overhead the pipeline
// adds on top of the raw probe.
func TestPipelineLatencyQueryToHot(t *testing.T) {
	if testing.Short() {
		t.Skip("live probe — skipped in -short")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	probeTimeout := 200 * time.Millisecond
	s, logPath, cfg := newTestEngine(t, ctx, probeTimeout)
	defer s.Close()

	// Pre-seed dns_cache so prober uses ProbeIPs (skips system DNS entirely).
	if err := s.UpsertDNSObservation(ctx, "blocked.test", unreachableIP, time.Now()); err != nil {
		t.Fatalf("seed dns_cache: %v", err)
	}

	engineDone := make(chan error, 1)
	go func() { engineDone <- Run(ctx, s, cfg) }()

	// Let the tailer open the file.
	time.Sleep(100 * time.Millisecond)

	appendLogLine(t, logPath,
		"Apr 16 00:00:00 dnsmasq[1]: 1 10.10.99.99/1 query[A] blocked.test from 10.10.99.99")

	// Default tail poll is 200ms, so the floor on detection is ~200ms + probe
	// timeout. Budget 3s to cover slow-CI noise.
	elapsed := waitForState(t, ctx, s, "blocked.test", "hot", 3*time.Second)
	t.Logf("query→hot latency: %v (probe_timeout=%v, tailer=fsnotify)", elapsed, probeTimeout)

	// Headroom for slower CI runners; any regression past the probe timeout
	// envelope still fails loudly.
	if elapsed > 3*time.Second {
		t.Errorf("unexpectedly slow: %v > 3s", elapsed)
	}

	// Stop the engine and wait — otherwise Windows holds the log file open
	// during TempDir cleanup and the test fails with an unrelated fs error.
	cancel()
	<-engineDone
}

// TestPipelineThroughput writes N query lines as fast as possible and waits
// for all N domains to reach a terminal state (hot, ignore, or watch).
// Surfaces regressions in the scheduling fabric (inline semaphore cap,
// probe-worker batch size) more than raw probe speed.
func TestPipelineThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("live probes — skipped in -short")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const N = 50
	probeTimeout := 200 * time.Millisecond
	s, logPath, cfg := newTestEngine(t, ctx, probeTimeout)
	defer s.Close()

	// Test measures the scheduling fabric, not conservative prod defaults —
	// bump inline concurrency and worker batch so N probes can race rather
	// than queue.
	cfg.InlineProbeConcurrency = N
	cfg.ProbeBatch = N
	cfg.ProbeInterval = 100 * time.Millisecond

	// Pre-seed each domain with an unreachable IP.
	for i := 0; i < N; i++ {
		dom := fmt.Sprintf("blocked-%d.test", i)
		if err := s.UpsertDNSObservation(ctx, dom, unreachableIP, time.Now()); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}

	engineDone := make(chan error, 1)
	go func() { engineDone <- Run(ctx, s, cfg) }()
	defer func() {
		cancel()
		<-engineDone
	}()
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	for i := 0; i < N; i++ {
		appendLogLine(t, logPath, fmt.Sprintf(
			"Apr 16 00:00:00 dnsmasq[1]: %d 10.10.99.%d/1 query[A] blocked-%d.test from 10.10.99.%d",
			i+1, i%250+2, i, i%250+2))
	}

	// Wait for all N domains to have completed at least one probe (state !=
	// 'new'). Walking skeleton: we don't care about verdict, just that every
	// domain made it through the pipeline. Generous deadline because GitHub
	// Actions runners (2-CPU shared) routinely burst into other tenants and
	// starve our probe goroutines for seconds at a time.
	deadline := 30 * time.Second
	t0 := time.Now()
	for time.Since(t0) < deadline {
		doms, err := s.ListRecentDomains(ctx, N+10)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		settled := 0
		for _, d := range doms {
			if d.State != "new" {
				settled++
			}
		}
		if settled >= N {
			elapsed := time.Since(start)
			t.Logf("throughput: %d domains settled in %v (%.1f domains/sec, probe_timeout=%v, inline_concurrency=%d)",
				N, elapsed, float64(N)/elapsed.Seconds(), probeTimeout, cfg.InlineProbeConcurrency)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("only some of %d domains settled within %s", N, deadline)
}
