package engine

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

// TestComputeDesiredIPs_ManualAllowNotInUnion is the inverse regression
// test for v0.3.1: manual-allow lives in a separate ipset (ladon_manual)
// populated by dnsmasq, so it must NOT leak into the engine-managed ipset
// (ladon_engine) — otherwise ladon's destructive reconcile would either
// double-add or, worse, strip dnsmasq's adds it doesn't recognize.
func TestComputeDesiredIPs_ManualAllowNotInUnion(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	now := time.Now().UTC()
	// Operator put openai.com in manual_entries and the tailer observed
	// some subdomain IPs in dns_cache. Engine's union must ignore both.
	if err := s.UpsertManual(ctx, "openai.com", "allow"); err != nil {
		t.Fatal(err)
	}
	mustObserve(t, s, "cdn.openai.com", "13.107.219.157", now)

	cfg := Defaults("/dev/null")
	cfg.IpsetName = ""
	desired, _, err := computeDesiredIPs(ctx, s, cfg)
	if err != nil {
		t.Fatalf("computeDesiredIPs: %v", err)
	}
	if len(desired) != 0 {
		t.Errorf("desired = %v, want empty — manual-allow must not feed engine ipset", desired)
	}
}

// TestComputeDesiredIPs_HotStillNeedsTwoConfirmed verifies we didn't loosen
// the gate for auto-classified domains: a single hot subdomain shouldn't
// pull all sibling IPs from dns_cache.
func TestComputeDesiredIPs_HotStillNeedsTwoConfirmed(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	now := time.Now().UTC()
	// One hot domain in fbcdn.net family. The other observed sibling is just
	// a DNS observation (not hot) — siblings should NOT be pulled.
	mustObserve(t, s, "video.fbcdn.net", "1.1.1.1", now)
	if err := s.UpsertHotEntry(ctx, "video.fbcdn.net", "tcp:fail", now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	mustObserve(t, s, "scontent.fbcdn.net", "2.2.2.2", now)

	cfg := Defaults("/dev/null")
	cfg.IpsetName = ""
	desired, _, err := computeDesiredIPs(ctx, s, cfg)
	if err != nil {
		t.Fatalf("computeDesiredIPs: %v", err)
	}

	if _, has := desired["1.1.1.1"]; !has {
		t.Errorf("hot domain's own IP missing")
	}
	if _, has := desired["2.2.2.2"]; has {
		t.Errorf("sibling IP leaked despite only 1 hot — the ≥2 gate must hold for auto-classified")
	}
}

// TestComputeDesiredIPs_HotWithTwoConfirmedExpands is the inverse: with two
// hot siblings, the family gate opens and the third (DNS-only) sibling's IP
// should also land in desired.
func TestComputeDesiredIPs_HotWithTwoConfirmedExpands(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	now := time.Now().UTC()
	for _, d := range []struct{ dom, ip string }{
		{"video.fbcdn.net", "1.1.1.1"},
		{"scontent.fbcdn.net", "2.2.2.2"},
		{"static.fbcdn.net", "3.3.3.3"},
	} {
		mustObserve(t, s, d.dom, d.ip, now)
	}
	if err := s.UpsertHotEntry(ctx, "video.fbcdn.net", "fail", now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertHotEntry(ctx, "scontent.fbcdn.net", "fail", now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	cfg := Defaults("/dev/null")
	cfg.IpsetName = ""
	desired, _, err := computeDesiredIPs(ctx, s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		if _, ok := desired[ip]; !ok {
			t.Errorf("missing %s — ≥2 hot siblings should pull whole family", ip)
		}
	}
}

func mustObserve(t *testing.T, s *storage.Store, domain, ip string, now time.Time) {
	t.Helper()
	ctx := context.Background()
	// Real ingest flow does both — UpsertDomain populates etld_plus_one which
	// LookupIPsByETLD's JOIN depends on.
	if err := s.UpsertDomain(ctx, domain, "", now); err != nil {
		t.Fatalf("upsert dom %s: %v", domain, err)
	}
	if err := s.UpsertDNSObservation(ctx, domain, ip, now); err != nil {
		t.Fatalf("observe %s: %v", domain, err)
	}
}
