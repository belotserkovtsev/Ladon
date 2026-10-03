package core

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// TestNewRequiresDBPath — without a database the engine has nowhere to
// accumulate, and that must show at once, not as lost state after a restart.
func TestNewRequiresDBPath(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("expected an error for an empty DBPath")
	}
}

// TestNewCreatesParentDirectory — an embedded engine is started like any
// program, with no installer to lay out its directories.
func TestNewCreatesParentDirectory(t *testing.T) {
	db := filepath.Join(t.TempDir(), "nested", "dir", "ladon.db")
	eng, err := New(Config{DBPath: db})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Close()
}

// TestRunTwiceRefused — two Runs on one engine would mean two sets of stages
// on one database.
func TestRunTwiceRefused(t *testing.T) {
	eng, err := New(Config{DBPath: filepath.Join(t.TempDir(), "ladon.db")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		eng.mu.RLock()
		up := eng.running
		eng.mu.RUnlock()
		if up {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := eng.Run(ctx); err == nil {
		t.Fatal("a second Run must be refused")
	}
}

// TestOnDNSIgnoresUnresolved — a name without addresses can be neither
// probed nor diverted, and the engine's sources drop it at the source. The
// embedded input must do the same, or the queue fills with empty observations.
func TestOnDNSIgnoresUnresolved(t *testing.T) {
	eng, err := New(Config{DBPath: filepath.Join(t.TempDir(), "ladon.db")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Close()

	eng.OnDNS("example.com", nil)
	eng.OnDNS("", []string{"93.184.216.34"})

	select {
	case obs := <-eng.src.ch:
		t.Fatalf("an unresolved name reached the queue: %+v", obs)
	default:
	}
}

// TestOnDNSNeverBlocks — the caller sits on the path of a DNS answer: when
// the queue is full the observation is lost, but the user's answer never waits.
func TestOnDNSNeverBlocks(t *testing.T) {
	eng, err := New(Config{DBPath: filepath.Join(t.TempDir(), "ladon.db")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 5000; i++ { // well past the source's buffer
			eng.OnDNS("example.com", []string{"93.184.216.34"})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("OnDNS blocked on a full queue")
	}
}

// TestVerdictDeliveredAndRemembered — the verdict must reach both whoever
// subscribed and whoever simply asks: a client subscribes to changes, but
// at start it needs the current list whole.
func TestVerdictDeliveredAndRemembered(t *testing.T) {
	eng, err := New(Config{DBPath: filepath.Join(t.TempDir(), "ladon.db")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Close()

	eng.publish([]string{"rutracker.org", "flibusta.is"})

	select {
	case v := <-eng.Verdicts():
		if len(v.Domains) != 2 || v.Domains[0] != "rutracker.org" {
			t.Fatalf("wrong verdict: %+v", v)
		}
		if v.At.IsZero() {
			t.Fatal("verdict without a timestamp")
		}
	case <-time.After(time.Second):
		t.Fatal("verdict not delivered to the subscriber")
	}

	if got := eng.Current(); len(got.Domains) != 2 {
		t.Fatalf("Current does not remember the verdict: %+v", got)
	}
}

// TestVerdictDropsWhenConsumerStalls — a lagging consumer must not stall
// the engine: updates are dropped, but Current stays true.
func TestVerdictDropsWhenConsumerStalls(t *testing.T) {
	eng, err := New(Config{DBPath: filepath.Join(t.TempDir(), "ladon.db"), VerdictBuffer: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			eng.publish([]string{"example.com"})
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("publish blocked on a consumer that is not listening")
	}
	if got := eng.Current(); len(got.Domains) != 1 {
		t.Fatalf("Current must know the latest verdict: %+v", got)
	}
}

// TestOnDNSDeniedReaches — a refusal must reach the engine rather than be
// dropped along with empty observations: the refusal is the evidence.
func TestOnDNSDeniedReaches(t *testing.T) {
	eng, err := New(Config{DBPath: filepath.Join(t.TempDir(), "ladon.db")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer eng.Close()

	eng.OnDNSDenied("rutracker.org")
	select {
	case obs := <-eng.src.ch:
		if obs.Domain != "rutracker.org" || !obs.Denied || len(obs.IPs) != 0 {
			t.Fatalf("wrong refusal: %+v", obs)
		}
	default:
		t.Fatal("the refusal did not reach the engine")
	}

	eng.OnDNSDenied("")
	select {
	case obs := <-eng.src.ch:
		t.Fatalf("an empty name reached the queue: %+v", obs)
	default:
	}
}
