package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/belotserkovtsev/ladon/internal/prober"
	"github.com/belotserkovtsev/ladon/internal/storage"
)

// TestExitCompare_OverrulesLocalFalsePositive runs the batch worker with both
// LocalProber (always fails — pre-seeded unreachable IP) and RemoteProber
// (always says OK — fake HTTP server). The combined verdict should be
// Ignore — local FAIL + remote OK alone would be Hot, but here we're
// asserting the methodological-FP path: both probers disagree → Ignore wins
// when remote returns OK after a separate failure mode.
//
// Wait — that's not the actual contract. Let me re-read decision-table:
// local FAIL + remote OK = Hot (real DPI block, exit confirms reachable)
// local FAIL + remote FAIL = Ignore (FP)
// So this test exercises the Hot path where both signals confirm: local
// can't reach but exit can, so domain belongs in tunnel. The interesting
// FP case is the second one.
func TestExitCompare_RemoteOKConfirmsHot(t *testing.T) {
	if testing.Short() {
		t.Skip("uses live local probe")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"dns_ok":true,"tcp_ok":true,"tls_ok":true,"reason":"ok","latency_ms":10}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	// Pre-seed an unreachable IP so the local probe will TCP-fail.
	if err := s.UpsertDNSObservation(ctx, "blocked.test", unreachableIP, time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.UpsertDomain(ctx, "blocked.test", "", time.Time{}); err != nil {
		t.Fatalf("upsert dom: %v", err)
	}

	cfg := Defaults("/dev/null")
	cfg.ProbeTimeout = 200 * time.Millisecond
	cfg.LocalProber = prober.NewLocal(cfg.ProbeTimeout)
	cfg.RemoteProber = prober.NewRemote(srv.URL, "", "", time.Second)

	trigger := make(chan struct{}, 1)
	probeDomain(ctx, s, cfg, "blocked.test", []chan<- struct{}{trigger}, true)

	hots, _ := s.ListHotEntries(ctx, time.Now().UTC())
	if len(hots) != 1 || hots[0] != "blocked.test" {
		t.Fatalf("want hot=[blocked.test], got %v — local FAIL + remote OK should give Hot", hots)
	}
}

// TestExitCompare_RemoteFailOverrulesLocalHot is the methodological-FP case.
// Local fails (port :443 unreachable, looks like a DPI drop), but remote also
// fails (the operator's vantage point also can't reach :443). That's a strong
// signal that the domain isn't blocked — it's just that probing :443 isn't
// the right test for this domain (think imap.gmail.com which lives on :993).
// Verdict must flip from Hot to Ignore, and any pre-existing hot_entries row
// for the domain must be cleared.
func TestExitCompare_RemoteFailOverrulesLocalHot(t *testing.T) {
	if testing.Short() {
		t.Skip("uses live local probe")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"dns_ok":true,"tcp_ok":false,"tls_ok":false,"reason":"tcp:timeout","latency_ms":805}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := s.UpsertDNSObservation(ctx, "blocked.test", unreachableIP, time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.UpsertDomain(ctx, "blocked.test", "", time.Time{}); err != nil {
		t.Fatalf("upsert dom: %v", err)
	}
	// Simulate prior inline-probe FP: domain is already in hot_entries.
	if err := s.UpsertHotEntry(ctx, "blocked.test", "tcp:earlier_fp", time.Now().Add(24*time.Hour)); err != nil {
		t.Fatalf("seed hot: %v", err)
	}

	cfg := Defaults("/dev/null")
	cfg.ProbeTimeout = 200 * time.Millisecond
	cfg.LocalProber = prober.NewLocal(cfg.ProbeTimeout)
	cfg.RemoteProber = prober.NewRemote(srv.URL, "", "", time.Second)

	trigger := make(chan struct{}, 1)
	probeDomain(ctx, s, cfg, "blocked.test", []chan<- struct{}{trigger}, true)

	hots, _ := s.ListHotEntries(ctx, time.Now().UTC())
	if len(hots) != 0 {
		t.Fatalf("want hot=[], got %v — local FAIL + remote FAIL should override to Ignore and clear hot_entries", hots)
	}
}

// TestExitCompare_RemoteTransportFailureKeepsHot is the safety case: when
// the operator's remote prober is itself unreachable (network error, timeout,
// non-200), we must NOT treat that as a remote-FAIL signal — otherwise a
// proxy outage would silently start un-tunneling real DPI blocks. Stick with
// the local Hot verdict; reason gets a 'remote:unavailable:' marker.
func TestExitCompare_RemoteTransportFailureKeepsHot(t *testing.T) {
	if testing.Short() {
		t.Skip("uses live local probe")
	}
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := s.UpsertDNSObservation(ctx, "blocked.test", unreachableIP, time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.UpsertDomain(ctx, "blocked.test", "", time.Time{}); err != nil {
		t.Fatalf("upsert dom: %v", err)
	}

	cfg := Defaults("/dev/null")
	cfg.ProbeTimeout = 200 * time.Millisecond
	cfg.LocalProber = prober.NewLocal(cfg.ProbeTimeout)
	// Point at a port no one listens on — RemoteProber returns
	// FailureReason="remote:dial tcp 127.0.0.1:1: connect: connection refused"
	cfg.RemoteProber = prober.NewRemote("http://127.0.0.1:1", "", "", 200*time.Millisecond)

	trigger := make(chan struct{}, 1)
	probeDomain(ctx, s, cfg, "blocked.test", []chan<- struct{}{trigger}, true)

	hots, _ := s.ListHotEntries(ctx, time.Now().UTC())
	if len(hots) != 1 || hots[0] != "blocked.test" {
		t.Fatalf("want hot=[blocked.test], got %v — remote transport failure must NOT override Hot", hots)
	}
}

// TestExitCompare_InlinePathSkipsRemote ensures the inline fast-path never
// hits the remote prober even when one is configured. Wired by passing
// useExitCompare=false; this test asserts that contract by giving the remote
// a hostile handler that records calls.
func TestExitCompare_InlinePathSkipsRemote(t *testing.T) {
	if testing.Short() {
		t.Skip("uses live local probe")
	}
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"tcp_ok":true,"tls_ok":true}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := s.UpsertDNSObservation(ctx, "blocked.test", unreachableIP, time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.UpsertDomain(ctx, "blocked.test", "", time.Time{}); err != nil {
		t.Fatalf("upsert dom: %v", err)
	}

	cfg := Defaults("/dev/null")
	cfg.ProbeTimeout = 200 * time.Millisecond
	cfg.LocalProber = prober.NewLocal(cfg.ProbeTimeout)
	cfg.RemoteProber = prober.NewRemote(srv.URL, "", "", time.Second)

	trigger := make(chan struct{}, 1)
	probeDomain(ctx, s, cfg, "blocked.test", []chan<- struct{}{trigger}, false) // inline path

	if called {
		t.Errorf("inline path must not call remote prober even when configured")
	}
}
