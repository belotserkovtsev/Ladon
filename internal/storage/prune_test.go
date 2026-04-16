package storage

import (
	"context"
	"path/filepath"
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
		if err := s.UpsertDomain(ctx, domain, "", time.Time{}); err != nil {
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

func mustExec(t *testing.T, s *Store, q string, args ...any) {
	t.Helper()
	if _, err := s.db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}
