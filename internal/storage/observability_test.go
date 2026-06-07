package storage

import (
	"context"
	"testing"
	"time"
)

func TestRuntimeMeta(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, ok, err := s.GetMeta(ctx, "missing"); err != nil || ok {
		t.Fatalf("GetMeta(missing): ok=%v err=%v", ok, err)
	}

	if err := s.SetMeta(ctx, "version", "v1.4.0"); err != nil {
		t.Fatalf("SetMeta: %v", err)
	}
	row, ok, err := s.GetMeta(ctx, "version")
	if err != nil || !ok || row.Value != "v1.4.0" {
		t.Fatalf("GetMeta: row=%+v ok=%v err=%v", row, ok, err)
	}
	if row.UpdatedAt == "" {
		t.Fatal("expected updated_at to be stamped")
	}

	// Upsert overwrites in place.
	if err := s.SetMeta(ctx, "version", "v1.5.0"); err != nil {
		t.Fatal(err)
	}
	if row, _, _ := s.GetMeta(ctx, "version"); row.Value != "v1.5.0" {
		t.Fatalf("upsert: got %q want v1.5.0", row.Value)
	}

	// Time round-trips through the storage layout.
	want := time.Date(2026, 6, 7, 10, 30, 15, 0, time.UTC)
	if err := s.SetMetaTime(ctx, "last_tick_at", want); err != nil {
		t.Fatal(err)
	}
	row, _, _ = s.GetMeta(ctx, "last_tick_at")
	got, valid, err := ParseTime(row.Value)
	if err != nil || !valid || !got.Equal(want) {
		t.Fatalf("SetMetaTime round-trip: got=%v valid=%v err=%v", got, valid, err)
	}

	all, err := s.AllMeta(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("AllMeta len=%d want 2", len(all))
	}
}

func TestObservabilityCounts(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	bp := func(v bool) *bool { return &v }

	mk := func(domain string) {
		if err := s.UpsertDomain(ctx, domain, now); err != nil {
			t.Fatalf("upsert %s: %v", domain, err)
		}
	}

	// A hot domain with a live backing row.
	mk("backed-hot.com")
	if err := s.UpsertHotEntry(ctx, "backed-hot.com", "tls_reset", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDomainState(ctx, "backed-hot.com", "hot", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// A hot domain whose backing row already expired (not swept yet).
	mk("expired-hot.com")
	if err := s.UpsertHotEntry(ctx, "expired-hot.com", "tcp_timeout", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDomainState(ctx, "expired-hot.com", "hot", now); err != nil {
		t.Fatal(err)
	}
	// A hot domain with NO backing row — orphaned drift.
	mk("orphan-hot.com")
	if err := s.SetDomainState(ctx, "orphan-hot.com", "hot", now); err != nil {
		t.Fatal(err)
	}
	// A durable cache domain.
	mk("cached.com")
	if err := s.PromoteCache(ctx, "cached.com", "repeated_block", now); err != nil {
		t.Fatal(err)
	}
	// Terminal states.
	mk("ignored.com")
	if err := s.SetDomainState(ctx, "ignored.com", "ignore", now); err != nil {
		t.Fatal(err)
	}
	mk("fresh.com") // stays 'new'

	// --- counts by state ---
	counts, err := s.CountDomainsByState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for st, want := range map[string]int{"hot": 3, "cache": 1, "ignore": 1, "new": 1} {
		if counts[st] != want {
			t.Errorf("state %q: got %d want %d (all=%v)", st, counts[st], want, counts)
		}
	}

	if n, _ := s.CountActiveHot(ctx, now); n != 1 {
		t.Errorf("CountActiveHot=%d want 1", n)
	}
	if n, _ := s.CountExpiredHot(ctx, now); n != 1 {
		t.Errorf("CountExpiredHot=%d want 1", n)
	}
	if n, _ := s.CountCacheRows(ctx); n != 1 {
		t.Errorf("CountCacheRows=%d want 1", n)
	}
	if n, _ := s.CountOrphanedDomains(ctx); n != 1 {
		t.Errorf("CountOrphanedDomains=%d want 1 (only orphan-hot.com)", n)
	}
	if n, _ := s.CountObservationsSince(ctx, now.Add(-time.Hour)); n != 6 {
		t.Errorf("CountObservationsSince=%d want 6", n)
	}

	// --- probe stats ---
	insertProbe := func(domain, verdict string) {
		id, err := s.InsertProbe(ctx, ProbeResult{
			Domain: domain, DNSOK: bp(true), TCPOK: bp(false), TLSOK: bp(false),
			FailureReason: "tcp_reset: connection reset",
		}, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if verdict != "" {
			if err := s.SetProbeVerdict(ctx, id, verdict); err != nil {
				t.Fatal(err)
			}
		}
	}
	insertProbe("backed-hot.com", "blocked")
	insertProbe("expired-hot.com", "blocked")
	insertProbe("ignored.com", "clear")
	insertProbe("fresh.com", "") // provisional inline row, no verdict

	total, blocked, clear, err := s.RecentProbeStats(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || blocked != 2 || clear != 1 {
		t.Errorf("RecentProbeStats total=%d blocked=%d clear=%d want 4/2/1", total, blocked, clear)
	}
	if _, ok, _ := s.LatestProbeAt(ctx); !ok {
		t.Error("LatestProbeAt: expected a probe")
	}
	if _, ok, _ := s.LatestObservationAt(ctx); !ok {
		t.Error("LatestObservationAt: expected an observation")
	}
}

func TestWhyHelpers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	bp := func(v bool) *bool { return &v }

	if _, ok, err := s.GetDomain(ctx, "nope.com"); err != nil || ok {
		t.Fatalf("GetDomain(unknown): ok=%v err=%v", ok, err)
	}

	if err := s.UpsertDomain(ctx, "cdn.example.com", now); err != nil {
		t.Fatal(err)
	}
	if err := s.PromoteCache(ctx, "cdn.example.com", "repeated_block", now); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDNSObservation(ctx, "cdn.example.com", "1.2.3.4", now); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDNSObservation(ctx, "cdn.example.com", "5.6.7.8", now); err != nil {
		t.Fatal(err)
	}
	id, err := s.InsertProbe(ctx, ProbeResult{
		Domain: "cdn.example.com", DNSOK: bp(true), TCPOK: bp(false), TLSOK: bp(false),
		FailureReason: "tls_reset: x",
	}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetProbeVerdict(ctx, id, "blocked"); err != nil {
		t.Fatal(err)
	}

	d, ok, err := s.GetDomain(ctx, "cdn.example.com")
	if err != nil || !ok {
		t.Fatalf("GetDomain: ok=%v err=%v", ok, err)
	}
	if d.State != "cache" {
		t.Errorf("state=%q want cache", d.State)
	}

	if at, reason, ok, _ := s.CacheEntryFor(ctx, "cdn.example.com"); !ok || at == "" || reason == "" {
		t.Errorf("CacheEntryFor: ok=%v at=%q reason=%q", ok, at, reason)
	}
	if _, _, ok, _ := s.HotEntryFor(ctx, "cdn.example.com"); ok {
		t.Error("HotEntryFor: cache domain should have no hot row")
	}

	ips, err := s.LookupAllIPs(ctx, "cdn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Errorf("LookupAllIPs=%v want 2", ips)
	}

	probes, err := s.RecentProbesForDomain(ctx, "cdn.example.com", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) != 1 || probes[0].Verdict != "blocked" {
		t.Fatalf("RecentProbesForDomain=%+v", probes)
	}
	dns, tcp, tls, _ := probes[0].Flags()
	if dns != "ok" || tcp != "x" || tls != "x" {
		t.Errorf("Flags dns=%s tcp=%s tls=%s want ok/x/x", dns, tcp, tls)
	}
}
