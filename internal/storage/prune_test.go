package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	old := time.Date(2026, 4, 14, 0, 0, 0, 0, time.UTC)
	cutoff := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 4, 16, 14, 0, 0, 0, time.UTC)

	mustUpsert := func(domain string) {
		if err := s.UpsertDomain(ctx, domain, time.Time{}); err != nil {
			t.Fatalf("upsert dom %s: %v", domain, err)
		}
	}

	// Seed a stale (pre-cutoff) and a fresh (post-cutoff) row in each table.
	mustUpsert("stale.test")
	mustUpsert("fresh.test")
	if err := s.UpsertHotEntry(ctx, "stale.test", "old", old.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Backdate it so created_at lies before the cutoff (UpsertHotEntry sets
	// created_at to time.Now()).
	mustExec(t, s, `UPDATE hot_entries SET created_at = ? WHERE domain = ?`,
		formatTime(old), "stale.test")
	if err := s.UpsertHotEntry(ctx, "fresh.test", "new", recent.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	mustExec(t, s, `UPDATE hot_entries SET created_at = ? WHERE domain = ?`,
		formatTime(recent), "fresh.test")

	if err := s.PromoteCache(ctx, "stale.test", "old", old); err != nil {
		t.Fatal(err)
	}
	if err := s.PromoteCache(ctx, "fresh.test", "new", recent); err != nil {
		t.Fatal(err)
	}

	dnsOK := true
	tcpFail := false
	for _, ts := range []time.Time{old, recent} {
		if _, err := s.InsertProbe(ctx, ProbeResult{
			Domain: "stale.test", DNSOK: &dnsOK, TCPOK: &tcpFail, TLSOK: &tcpFail,
		}, ts); err != nil {
			t.Fatal(err)
		}
	}

	// Count snapshot.
	if n, _ := s.CountCache(ctx, time.Time{}); n != 2 {
		t.Errorf("cache count = %d, want 2", n)
	}
	if n, _ := s.CountCache(ctx, cutoff); n != 1 {
		t.Errorf("cache count before cutoff = %d, want 1 (stale)", n)
	}

	// Prune cache before cutoff — should remove only the stale row.
	if n, err := s.PruneCache(ctx, cutoff); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Errorf("pruned cache rows = %d, want 1", n)
	}
	if n, _ := s.CountCache(ctx, time.Time{}); n != 1 {
		t.Errorf("cache after prune = %d, want 1", n)
	}

	// PromoteCache moves a domain out of the hot tier (drops its hot_entries
	// row), so the promotions above left hot_entries empty. Seed dedicated
	// hot-only rows to exercise the hot prune.
	_ = s.UpsertHotEntry(ctx, "hot-stale.test", "old", old.Add(24*time.Hour))
	mustExec(t, s, `UPDATE hot_entries SET created_at = ? WHERE domain = ?`, formatTime(old), "hot-stale.test")
	_ = s.UpsertHotEntry(ctx, "hot-fresh.test", "new", recent.Add(24*time.Hour))
	mustExec(t, s, `UPDATE hot_entries SET created_at = ? WHERE domain = ?`, formatTime(recent), "hot-fresh.test")

	// Prune hot before cutoff — same shape.
	if n, err := s.PruneHot(ctx, cutoff); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Errorf("pruned hot rows = %d, want 1", n)
	}

	// Probes: no -before clears all.
	if n, err := s.PruneProbes(ctx, time.Time{}); err != nil {
		t.Fatal(err)
	} else if n != 2 {
		t.Errorf("pruned probes = %d, want 2", n)
	}

	// stale.test no longer has hot or cache rows; should be reset to 'new'.
	// fresh.test still has both — should not be touched.
	if n, err := s.ResetOrphanedDomains(ctx); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Errorf("orphaned reset = %d, want 1", n)
	}
}

// TestPruneDNSCacheAndCheckpoint covers the maintenance helpers: PruneDNSCache
// deletes by last_seen_at (not created_at), and Checkpoint must not error on a
// healthy DB.
func TestPruneDNSCacheAndCheckpoint(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	old := time.Date(2026, 4, 14, 0, 0, 0, 0, time.UTC)
	cutoff := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 4, 16, 14, 0, 0, 0, time.UTC)

	if err := s.UpsertDNSObservation(ctx, "stale.test", "1.1.1.1", old); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDNSObservation(ctx, "fresh.test", "2.2.2.2", recent); err != nil {
		t.Fatal(err)
	}

	n, err := s.PruneDNSCache(ctx, cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("pruned dns_cache rows = %d, want 1 (stale only)", n)
	}

	var remaining int
	if err := s.rdb.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_cache`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Errorf("dns_cache rows after prune = %d, want 1 (fresh survives)", remaining)
	}

	// Best-effort WAL checkpoint must succeed on a healthy DB.
	if err := s.Checkpoint(ctx); err != nil {
		t.Errorf("checkpoint: %v", err)
	}
}

// TestPromoteCacheDropsHotEntry verifies promotion moves a domain out of the
// hot tier: the hot_entries row is removed (so the scorer's ListHotEntries
// can't re-promote it every cycle), the domain lands in cache_entries, and the
// hot DPI reason is folded into the cache reason.
func TestPromoteCacheDropsHotEntry(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	now := time.Now().UTC()
	if err := s.UpsertDomain(ctx, "x.test", now); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDomainState(ctx, "x.test", "hot", now); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertHotEntry(ctx, "x.test", "local:tls13_block", now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := s.PromoteCache(ctx, "x.test", "repeated_block", now); err != nil {
		t.Fatal(err)
	}

	// Hot tier: gone — the scorer iterates ListHotEntries, so a lingering row
	// would make it re-promote x.test on every pass.
	hots, err := s.ListHotEntries(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range hots {
		if d == "x.test" {
			t.Fatalf("x.test still in hot_entries after promotion: %v", hots)
		}
	}

	// Cache tier: present, with the hot DPI reason folded into the cache reason.
	var reason sql.NullString
	if err := s.rdb.QueryRowContext(ctx,
		`SELECT reason FROM cache_entries WHERE domain = 'x.test'`).Scan(&reason); err != nil {
		t.Fatalf("cache row missing: %v", err)
	}
	if !reason.Valid || !strings.Contains(reason.String, "repeated_block") || !strings.Contains(reason.String, "tls13_block") {
		t.Errorf("cache reason = %q, want both repeated_block and the hot DPI reason folded in", reason.String)
	}
}

func mustExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.wdb.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}
