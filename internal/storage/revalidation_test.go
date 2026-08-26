package storage

import (
	"context"
	"testing"
	"time"
)

func revalState(t *testing.T, s *Store, domain string) string {
	t.Helper()
	var st string
	if err := s.rdb.QueryRowContext(context.Background(),
		`SELECT state FROM domains WHERE domain = ?`, domain).Scan(&st); err != nil {
		t.Fatalf("read state %s: %v", domain, err)
	}
	return st
}

func revalCacheRows(t *testing.T, s *Store, domain string) int {
	t.Helper()
	var n int
	if err := s.rdb.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM cache_entries WHERE domain = ?`, domain).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestApplyRevalidationResetsAfterStreak(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_ = s.UpsertDomain(ctx, "lifted.test", now)
	if err := s.PromoteCache(ctx, "lifted.test", "repeated_block", now); err != nil {
		t.Fatal(err)
	}
	if got := revalState(t, s, "lifted.test"); got != "cache" {
		t.Fatalf("setup: want cache, got %q", got)
	}

	// Two disagreeing probes stay pending — no flip before threshold.
	for i := 1; i <= 2; i++ {
		action, streak, err := s.ApplyRevalidation(ctx, "lifted.test", true, 3, now)
		if err != nil {
			t.Fatal(err)
		}
		if action != "pending" || streak != i {
			t.Fatalf("probe %d: want pending/%d, got %s/%d", i, i, action, streak)
		}
	}
	if got := revalState(t, s, "lifted.test"); got != "cache" {
		t.Fatalf("must still be cache before threshold, got %q", got)
	}

	// Third disagreement hits threshold → reset to new, tunnel membership shed.
	action, _, err := s.ApplyRevalidation(ctx, "lifted.test", true, 3, now)
	if err != nil {
		t.Fatal(err)
	}
	if action != "reset" {
		t.Fatalf("want reset, got %s", action)
	}
	if got := revalState(t, s, "lifted.test"); got != "new" {
		t.Fatalf("want new after reset, got %q", got)
	}
	if revalCacheRows(t, s, "lifted.test") != 0 {
		t.Fatal("cache_entries row should be gone after reset")
	}
}

func TestApplyRevalidationAgreeResetsStreak(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.UpsertDomain(ctx, "solid.test", now)
	_ = s.PromoteCache(ctx, "solid.test", "repeated_block", now)

	if _, streak, _ := s.ApplyRevalidation(ctx, "solid.test", true, 3, now); streak != 1 {
		t.Fatalf("want streak 1, got %d", streak)
	}
	// An agreeing probe clears the streak and keeps the state.
	if action, streak, _ := s.ApplyRevalidation(ctx, "solid.test", false, 3, now); action != "kept" || streak != 0 {
		t.Fatalf("want kept/0, got %s/%d", action, streak)
	}
	if got := revalState(t, s, "solid.test"); got != "cache" {
		t.Fatalf("agreeing probe must keep cache, got %q", got)
	}
}

func TestListRevalidationCandidates(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// cache + ignore are candidates; new + hot are not.
	_ = s.UpsertDomain(ctx, "c.test", now)
	_ = s.PromoteCache(ctx, "c.test", "b", now)
	_ = s.UpsertDomain(ctx, "i.test", now)
	_ = s.SetDomainState(ctx, "i.test", "ignore", time.Time{})
	_ = s.UpsertDomain(ctx, "n.test", now) // stays new
	_ = s.UpsertDomain(ctx, "h.test", now)
	_ = s.SetDomainState(ctx, "h.test", "hot", time.Time{})

	got, err := s.ListRevalidationCandidates(ctx, 10, now)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, d := range got {
		set[d.Domain] = true
	}
	if !set["c.test"] || !set["i.test"] {
		t.Fatalf("cache+ignore must be candidates, got %v", set)
	}
	if set["n.test"] || set["h.test"] {
		t.Fatalf("new/hot must NOT be candidates, got %v", set)
	}

	// A probe stamps reval_at=now, so the domain isn't due again until interval passes.
	if _, _, err := s.ApplyRevalidation(ctx, "c.test", false, 3, now); err != nil {
		t.Fatal(err)
	}
	got2, err := s.ListRevalidationCandidates(ctx, 10, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range got2 {
		if d.Domain == "c.test" {
			t.Fatal("freshly-stamped c.test should not be due")
		}
	}
}
