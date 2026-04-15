package scorer

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

// newStoreWithHot sets up a store with one domain in hot_entries and inserts
// `fails` failing probes spread across the last `spread` duration. Returns
// the store for the caller to verify promotion outcomes.
func newStoreWithHot(t *testing.T, domain string, fails int, spread time.Duration) *storage.Store {
	t.Helper()
	ctx := context.Background()
	s, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	now := time.Now().UTC()
	_ = s.UpsertDomain(ctx, domain, "", now)
	_ = s.SetDomainState(ctx, domain, "hot", now)
	_ = s.UpsertHotEntry(ctx, domain, "tcp_connect_failed", now.Add(24*time.Hour))

	// Spread fails linearly across `spread` duration, all within window.
	fail := false
	ok := true
	step := spread / time.Duration(fails+1)
	for i := 0; i < fails; i++ {
		at := now.Add(-time.Duration(i+1) * step)
		if _, err := s.InsertProbe(ctx, storage.ProbeResult{
			Domain: domain,
			DNSOK:  &ok, TCPOK: &fail, TLSOK: &fail,
		}, at); err != nil {
			t.Fatalf("insert probe: %v", err)
		}
	}
	return s
}

// runPromoteOnce kicks a single scorer pass and stops the goroutine.
func runPromoteOnce(t *testing.T, s *storage.Store, cfg Config) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Interval huge so only the initial pass fires; cancel soon after.
	cfg.Interval = time.Hour
	done := make(chan struct{})
	go func() {
		_ = Run(ctx, s, cfg)
		close(done)
	}()
	time.Sleep(200 * time.Millisecond) // let initial promote() complete
	cancel()
	<-done
}

func TestPromotesWhenThresholdMet(t *testing.T) {
	s := newStoreWithHot(t, "blocked.test", 5, time.Hour)
	ctx := context.Background()

	runPromoteOnce(t, s, Config{Window: 2 * time.Hour, FailThreshold: 3})

	cache, err := s.ListCacheEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cache) != 1 || cache[0] != "blocked.test" {
		t.Fatalf("want blocked.test in cache, got %v", cache)
	}
}

func TestDoesNotPromoteBelowThreshold(t *testing.T) {
	s := newStoreWithHot(t, "flaky.test", 2, time.Hour)
	ctx := context.Background()

	runPromoteOnce(t, s, Config{Window: 2 * time.Hour, FailThreshold: 5})

	cache, err := s.ListCacheEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cache) != 0 {
		t.Fatalf("expected no promotions below threshold, got %v", cache)
	}
}

func TestIgnoresFailsOutsideWindow(t *testing.T) {
	// 5 fails but they're spread 48h back — promote with a 1h window should see zero.
	s := newStoreWithHot(t, "stale.test", 5, 48*time.Hour)
	ctx := context.Background()

	runPromoteOnce(t, s, Config{Window: time.Hour, FailThreshold: 3})

	cache, err := s.ListCacheEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cache) != 0 {
		t.Fatalf("expected no promotions when all fails outside window, got %v", cache)
	}
}
