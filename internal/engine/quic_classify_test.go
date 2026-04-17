package engine

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/belotserkovtsev/ladon/internal/prober"
	"github.com/belotserkovtsev/ladon/internal/storage"
)

// fakeQUICProber returns a canned result — lets tests exercise the
// classifier without a real QUIC dial.
type fakeQUICProber struct {
	result prober.Result
}

func (f *fakeQUICProber) Name() string { return "fake-quic" }
func (f *fakeQUICProber) Probe(ctx context.Context, req prober.ProbeRequest) prober.Result {
	r := f.result
	r.Domain = req.Domain
	r.Proto = "quic"
	return r
}

// fakeLocalProber returns a canned Result for the TCP+TLS path — lets the
// sticky-HOT test exercise probeDomain without a live TCP dial.
type fakeLocalProber struct {
	result prober.Result
}

func (f *fakeLocalProber) Name() string { return "fake-local" }
func (f *fakeLocalProber) Probe(ctx context.Context, req prober.ProbeRequest) prober.Result {
	r := f.result
	if r.Domain == "" {
		r.Domain = req.Domain
	}
	if r.Proto == "" {
		r.Proto = "tcp+tls"
	}
	return r
}

// TestQUICClassify_PromotesWhenTCPOKAndQUICFailAndUDPObserved is the happy
// path for step 6's promote rule. Seeds: domain in `ignore` state, tcp+tls
// probe on record as OK, observed_flows shows LAN client used UDP:443.
// Fake QUICProber returns fail. After probeDomainQUIC the domain must be
// HOT in both domains.state and hot_entries.
func TestQUICClassify_PromotesWhenTCPOKAndQUICFailAndUDPObserved(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	now := time.Now().UTC()
	tt := true
	seedDomain(t, s, "voice.test", "162.159.138.232", now, &tt, &tt) // tcp+tls ok
	must(t, s.InsertObservedFlow(ctx, "162.159.138.232", "udp", 443, "192.168.0.53", now))

	cfg := Defaults("/dev/null")
	cfg.QUICProber = &fakeQUICProber{
		result: prober.Result{FailureReason: "quic:timeout"},
	}
	cfg.HotTTL = time.Hour
	cfg.ProbeCooldown = 10 * time.Minute

	trigger := make(chan struct{}, 1)
	probeDomainQUIC(ctx, s, cfg, "voice.test", trigger)

	// Hot entry written — observable proof of promote
	hots, err := s.ListHotEntries(ctx, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, h := range hots {
		if h == "voice.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("hot entry not written; got %v", hots)
	}
	// ipset trigger should be signalled
	select {
	case <-trigger:
	default:
		t.Errorf("ipset trigger not signalled")
	}
}

// TestQUICClassify_SkipsWhenNoUDPEvidence — no UDP flow in observed_flows
// means the QUIC-blocked signal has no client to fix. Promote should
// not fire even though TCP+TLS OK + QUIC fail.
func TestQUICClassify_SkipsWhenNoUDPEvidence(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Now().UTC()
	tt := true
	seedDomain(t, s, "tcp-only.test", "1.2.3.4", now, &tt, &tt)
	// NO observed_flows insert — domain has no UDP usage

	cfg := Defaults("/dev/null")
	cfg.QUICProber = &fakeQUICProber{result: prober.Result{FailureReason: "quic:timeout"}}
	trigger := make(chan struct{}, 1)
	probeDomainQUIC(ctx, s, cfg, "tcp-only.test", trigger)

	hots, _ := s.ListHotEntries(ctx, time.Now().UTC())
	for _, h := range hots {
		if h == "tcp-only.test" {
			t.Errorf("promoted without UDP evidence — rule misfired")
		}
	}
	select {
	case <-trigger:
		t.Errorf("trigger signalled when no promote should fire")
	default:
	}
}

// TestQUICClassify_SkipsWhenTCPAlsoFailed — if TCP already failed the
// normal pipeline handles promotion. QUIC classifier shouldn't duplicate
// work here (and shouldn't overwrite the TCP-provenance hot_entries row).
func TestQUICClassify_SkipsWhenTCPAlsoFailed(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Now().UTC()
	ff := false
	seedDomain(t, s, "dualblocked.test", "5.5.5.5", now, &ff, &ff)
	must(t, s.InsertObservedFlow(ctx, "5.5.5.5", "udp", 443, "192.168.0.53", now))

	cfg := Defaults("/dev/null")
	cfg.QUICProber = &fakeQUICProber{result: prober.Result{FailureReason: "quic:timeout"}}
	trigger := make(chan struct{}, 1)
	probeDomainQUIC(ctx, s, cfg, "dualblocked.test", trigger)

	select {
	case <-trigger:
		t.Errorf("classify should defer to TCP pipeline when TCP also failed")
	default:
	}
}

// TestQUICClassify_SkipsOnCRYPTOError validates the v1.0 post-deploy
// tightening: CRYPTO_ERROR / TLS handshake rejects from the server are NOT
// DPI evidence (confirmed via exit-compare — same codes from offshore
// vantage points). Only timeout-class failures should trigger promote.
func TestQUICClassify_SkipsOnCRYPTOError(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Now().UTC()
	tt := true
	seedDomain(t, s, "server-rejects-h3.test", "1.2.3.4", now, &tt, &tt)
	must(t, s.InsertObservedFlow(ctx, "1.2.3.4", "udp", 443, "192.168.0.50", now))

	cfg := Defaults("/dev/null")
	cfg.QUICProber = &fakeQUICProber{
		result: prober.Result{FailureReason: "quic:CRYPTO_ERROR 0x128 (remote): tls: handshake failure"},
	}
	trigger := make(chan struct{}, 1)
	probeDomainQUIC(ctx, s, cfg, "server-rejects-h3.test", trigger)

	hots, _ := s.ListHotEntries(ctx, time.Now().UTC())
	for _, h := range hots {
		if h == "server-rejects-h3.test" {
			t.Errorf("CRYPTO_ERROR must not promote — server-side reject, not DPI")
		}
	}
	select {
	case <-trigger:
		t.Errorf("trigger signalled on CRYPTO_ERROR")
	default:
	}
}

// TestQUICClassify_StickyHotOnTCPOK — the inverse half of the classifier:
// once QUIC has promoted a domain to HOT with reason "(udp-observed)",
// the next TCP+TLS probe returning OK should NOT demote it. Pre-v1.0 the
// Ignore case unconditionally deleted hot_entries; that would un-do every
// QUIC promote on the 5-minute ProbeCooldown tick.
func TestQUICClassify_StickyHotOnTCPOK(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Now().UTC()

	// Seed: domain with TCP+TLS OK history, currently in HOT via a prior
	// QUIC-promote (reason contains "udp-observed" marker).
	tt := true
	seedDomain(t, s, "udp-blocked.test", "9.9.9.9", now, &tt, &tt)
	must(t, s.UpsertHotEntry(ctx, "udp-blocked.test",
		"tcp+tls:ok|quic:quic:timeout (udp-observed)",
		now.Add(24*time.Hour)))

	// Now simulate what runProbeWorker does when the domain's cooldown
	// expires: run probeDomain which does a TCP+TLS probe (we'll fake an
	// OK Result via the LocalProber stub).
	cfg := Defaults("/dev/null")
	cfg.LocalProber = &fakeLocalProber{result: prober.Result{
		Domain: "udp-blocked.test", Proto: "tcp+tls",
		DNSOK: true, TCPOK: true, TLSOK: true,
	}}
	trigger := make(chan struct{}, 1)
	probeDomain(ctx, s, cfg, "udp-blocked.test", trigger, false)

	// Hot entry must still be present — QUIC-promoted records are sticky
	// against TCP-OK verdicts.
	hots, _ := s.ListHotEntries(ctx, time.Now().UTC())
	found := false
	for _, h := range hots {
		if h == "udp-blocked.test" {
			found = true
		}
	}
	if !found {
		t.Errorf("QUIC-promoted HOT was demoted by TCP+TLS OK — sticky logic broken")
	}
}

// TestQUICClassify_SkipsOnQUICSuccess — if QUIC handshake completes, no
// reason to promote anything.
func TestQUICClassify_SkipsOnQUICSuccess(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	now := time.Now().UTC()
	tt := true
	seedDomain(t, s, "healthy.test", "9.9.9.9", now, &tt, &tt)
	must(t, s.InsertObservedFlow(ctx, "9.9.9.9", "udp", 443, "192.168.0.53", now))

	cfg := Defaults("/dev/null")
	cfg.QUICProber = &fakeQUICProber{
		result: prober.Result{TCPOK: true, TLSOK: true}, // handshake completed
	}
	trigger := make(chan struct{}, 1)
	probeDomainQUIC(ctx, s, cfg, "healthy.test", trigger)

	select {
	case <-trigger:
		t.Errorf("QUIC OK must not trigger promote")
	default:
	}
}

// --- helpers ---

func newStore(t *testing.T) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

func seedDomain(t *testing.T, s *storage.Store, domain, ip string, now time.Time, tcpOK, tlsOK *bool) {
	t.Helper()
	ctx := context.Background()
	must(t, s.UpsertDomain(ctx, domain, "", now))
	must(t, s.UpsertDNSObservation(ctx, domain, ip, now))
	// Record a tcp+tls probe row so LatestProbeOK has data to read.
	if _, err := s.InsertProbe(ctx, storage.ProbeResult{
		Domain: domain,
		Proto:  "tcp+tls",
		TCPOK:  tcpOK,
		TLSOK:  tlsOK,
	}, now); err != nil {
		t.Fatal(err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
