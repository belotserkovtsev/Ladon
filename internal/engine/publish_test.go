package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

func publishStore(t *testing.T) (*storage.Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	s, err := storage.Open(filepath.Join(t.TempDir(), "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	return s, ctx
}

// waitFor gives a background stage a moment to do its work without pinning the
// test to a fixed sleep.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// The file is the whole point of the stage: whatever enforces the verdict
// downstream reads it, so it has to carry exactly the domains ladon routes and
// nothing it merely looked at.
func TestPublisherWritesTheBlockedDomains(t *testing.T) {
	s, ctx := publishStore(t)
	now := time.Now().UTC()

	for _, d := range []string{"hot.test", "cache.test", "covered.test", "ignored.test", "fresh.test"} {
		if err := s.UpsertDomain(ctx, d, now); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.SetDomainState(ctx, "hot.test", "hot", time.Time{})
	_ = s.SetDomainState(ctx, "cache.test", "cache", time.Time{})
	_ = s.SetDomainState(ctx, "covered.test", "covered", time.Time{})
	_ = s.SetDomainState(ctx, "ignored.test", "ignore", time.Time{})
	// fresh.test stays 'new'

	out := filepath.Join(t.TempDir(), "blocked.txt")
	cfg := Defaults("")
	cfg.Publish = PublishConfig{Path: out, Interval: 20 * time.Millisecond}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = runVerdictPublisher(runCtx, s, cfg) }()

	if !waitFor(t, 3*time.Second, func() bool { _, err := os.Stat(out); return err == nil }) {
		t.Fatal("publisher never wrote the file")
	}
	body, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)

	for _, want := range []string{"hot.test", "cache.test", "covered.test"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q missing — it is routed, so it belongs in the file:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"ignored.test", "fresh.test"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("%q present — it is not routed and must not be:\n%s", unwanted, got)
		}
	}
}

// Consumers poll this file. Rewriting an identical one would have them reload
// for nothing, so an unchanged verdict must leave the file alone.
func TestPublisherLeavesAnUnchangedFileAlone(t *testing.T) {
	s, ctx := publishStore(t)
	_ = s.UpsertDomain(ctx, "blocked.test", time.Now().UTC())
	_ = s.SetDomainState(ctx, "blocked.test", "cache", time.Time{})

	out := filepath.Join(t.TempDir(), "blocked.txt")
	cfg := Defaults("")
	cfg.Publish = PublishConfig{Path: out, Interval: 20 * time.Millisecond}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = runVerdictPublisher(runCtx, s, cfg) }()

	if !waitFor(t, 3*time.Second, func() bool { _, err := os.Stat(out); return err == nil }) {
		t.Fatal("publisher never wrote the file")
	}
	first, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	// Several intervals pass with nothing changing in the database.
	time.Sleep(300 * time.Millisecond)
	second, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if !first.ModTime().Equal(second.ModTime()) {
		t.Error("file was rewritten though the verdict never changed")
	}

	// A new blocked domain is a real change and has to land.
	_ = s.UpsertDomain(ctx, "another.test", time.Now().UTC())
	_ = s.SetDomainState(ctx, "another.test", "hot", time.Time{})
	ok := waitFor(t, 3*time.Second, func() bool {
		b, err := os.ReadFile(out)
		return err == nil && strings.Contains(string(b), "another.test")
	})
	if !ok {
		t.Error("a newly blocked domain never reached the file")
	}
}

// Without a path there is nothing to publish, and the stage must not exit —
// the engine treats an early return as a failure and brings the daemon down.
func TestPublisherStaysParkedWithoutAPath(t *testing.T) {
	s, ctx := publishStore(t)
	runCtx, cancel := context.WithCancel(ctx)

	done := make(chan error, 1)
	go func() { done <- runVerdictPublisher(runCtx, s, Defaults("")) }()

	select {
	case <-done:
		t.Fatal("returned while the daemon was still running")
	case <-time.After(200 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("shutdown returned %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("did not unwind on shutdown")
	}
}

// The cached body says what was written last, not what is on disk. If anything
// removes the file — a cleanup job, a tmpfs that did not survive a reboot, an
// operator tidying up — whoever reads it is acting on nothing at all, and the
// cache would keep it that way until the verdict happened to change.
func TestPublisherRestoresAFileRemovedUnderneathIt(t *testing.T) {
	s, ctx := publishStore(t)
	_ = s.UpsertDomain(ctx, "blocked.test", time.Now().UTC())
	_ = s.SetDomainState(ctx, "blocked.test", "cache", time.Time{})

	out := filepath.Join(t.TempDir(), "blocked.txt")
	cfg := Defaults("")
	cfg.Publish = PublishConfig{Path: out, Interval: 20 * time.Millisecond}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = runVerdictPublisher(runCtx, s, cfg) }()

	if !waitFor(t, 3*time.Second, func() bool { _, err := os.Stat(out); return err == nil }) {
		t.Fatal("publisher never wrote the file")
	}
	if err := os.Remove(out); err != nil {
		t.Fatal(err)
	}

	ok := waitFor(t, 3*time.Second, func() bool {
		b, err := os.ReadFile(out)
		return err == nil && strings.Contains(string(b), "blocked.test")
	})
	if !ok {
		t.Error("the file never came back — the verdict had not changed, so the cache kept it gone")
	}
}

// The path is somebody's choice in a config file. A directory that is not there
// yet should not cost an unwritten verdict every minute for as long as the
// daemon runs.
func TestPublisherCreatesTheDirectory(t *testing.T) {
	s, ctx := publishStore(t)
	_ = s.UpsertDomain(ctx, "blocked.test", time.Now().UTC())
	_ = s.SetDomainState(ctx, "blocked.test", "cache", time.Time{})

	out := filepath.Join(t.TempDir(), "state", "published", "blocked.txt")
	cfg := Defaults("")
	cfg.Publish = PublishConfig{Path: out, Interval: 20 * time.Millisecond}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = runVerdictPublisher(runCtx, s, cfg) }()

	ok := waitFor(t, 3*time.Second, func() bool {
		b, err := os.ReadFile(out)
		return err == nil && strings.Contains(string(b), "blocked.test")
	})
	if !ok {
		t.Error("nothing written — the directory did not exist and was not created")
	}
}
