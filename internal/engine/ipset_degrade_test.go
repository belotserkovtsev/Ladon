package engine

import (
	"context"
	"testing"
	"time"
)

// An unusable set is a host problem — the set is missing, or `ipset` is not
// installed at all — and no amount of restarting fixes it. Returning early
// makes the engine report a failure, the daemon exits, the service manager
// starts it again, and each start bounces dnsmasq: DNS flaps for everyone
// behind the gateway while the actual cause sits untouched.
//
// So the stage has to stay put and let the rest of the daemon work.
func TestIpsetSyncerParksWhenTheSetIsUnusable(t *testing.T) {
	s, ctx := publishStore(t)

	cfg := Defaults("")
	// A set this name will not exist, and on a host without ipset the lookup
	// fails outright — both are the paths this test is about.
	cfg.IpsetName = "ladon_test_definitely_absent"
	cfg.IpsetInterval = 20 * time.Millisecond

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- runIpsetSyncer(runCtx, s, cfg, make(chan struct{})) }()

	select {
	case <-done:
		t.Fatal("returned while the daemon was still running — this is what takes DNS down with it")
	case <-time.After(300 * time.Millisecond):
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

// The same when the operator turns the engine set off outright.
func TestIpsetSyncerParksWhenDisabled(t *testing.T) {
	s, ctx := publishStore(t)
	cfg := Defaults("")
	cfg.IpsetName = ""

	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- runIpsetSyncer(runCtx, s, cfg, make(chan struct{})) }()

	select {
	case <-done:
		t.Fatal("returned instead of parking")
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
