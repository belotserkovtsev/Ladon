package ladon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/belotserkovtsev/ladon/internal/publisher"
)

// writeCfg builds the JSON config string that New consumes, pointing at a
// per-test tmpdir so tests don't collide on disk.
func writeCfg(t *testing.T, dir string) string {
	t.Helper()
	cfg := Config{
		DBPath:                 filepath.Join(dir, "engine.db"),
		SnapshotPath:           filepath.Join(dir, "hot-snapshot.json"),
		ProbeTimeoutMS:         200,
		InlineProbeConcurrency: 2,
		// Publish often so tests don't wait through the default 10s cadence.
		PublishIntervalSec: 1,
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal cfg: %v", err)
	}
	return string(b)
}

// TestNewAndShutdown checks the smallest lifecycle: construct, start, stop.
// A freshly-created engine must accept Start then Shutdown without
// leaving dangling goroutines or file handles.
func TestNewAndShutdown(t *testing.T) {
	dir := t.TempDir()
	eng, err := New(writeCfg(t, dir))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := eng.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// TestStartIdempotent verifies double-Start is a no-op and double-Shutdown
// is a no-op. NE extensions can be resurrected by iOS mid-lifecycle and
// Swift callers shouldn't need to track whether start already fired.
func TestStartIdempotent(t *testing.T) {
	dir := t.TempDir()
	eng, err := New(writeCfg(t, dir))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("first start: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("second start: %v", err)
	}
	if err := eng.Shutdown(); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := eng.Shutdown(); err != nil {
		t.Fatalf("second shutdown: %v", err)
	}
}

// TestOnDNSQueryPersists routes a DNS event through the exported API and
// checks that the snapshot publisher eventually includes the resolved IPs
// for the queried domain. Covers the full chain:
//
//	Swift JSON → OnDNSQuery → goroutine → Runtime.OnDNSEvent →
//	  watcher.Ingest + UpsertDNSObservation → tryInlineProbe →
//	  (probe fails to resolve test-only domain) → UpsertHot →
//	  signalHotChanged → runPublisher → PublishSnapshotJSON → disk
//
// Using a non-resolvable domain makes the probe fail fast (DNS error), so
// the classifier promotes it to hot deterministically, and we can assert
// on the snapshot without waiting on real network.
func TestOnDNSQueryPersists(t *testing.T) {
	dir := t.TempDir()
	eng, err := New(writeCfg(t, dir))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := eng.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = eng.Shutdown() })

	const domain = "nonexistent.ladon-test.invalid"
	ipsJSON := `["203.0.113.10","203.0.113.11"]`
	eng.OnDNSQuery(domain, ipsJSON)

	// The engine's goroutine chain is: dispatch → ingest (ms) → probe
	// (~200ms configured timeout) → publisher debounce (up to 1s tick).
	// Poll the snapshot up to 5s; fail if the domain never surfaces.
	snapPath := filepath.Join(dir, "hot-snapshot.json")
	deadline := time.Now().Add(5 * time.Second)
	var snap publisher.Snapshot
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(snapPath)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		_ = json.Unmarshal(data, &snap)
		if hotContains(snap, domain) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !hotContains(snap, domain) {
		t.Fatalf("domain %q never appeared in snapshot.hot; snap=%s", domain, dumpSnap(snap))
	}
	// Observed IPs should have been upserted into dns_cache; at least one
	// should surface via the snapshot's IP join.
	entry := hotEntry(snap, domain)
	if len(entry.IPs) == 0 {
		t.Errorf("hot entry for %q has no IPs — expected at least one of 203.0.113.10/11; snap=%s",
			domain, dumpSnap(snap))
	}
}

// TestOnDNSQueryWhenStopped should not panic or produce work — stopped
// engines drop events silently. Shutdown is still required to release the
// DB handle so the tmpdir cleanup can run on Windows.
func TestOnDNSQueryWhenStopped(t *testing.T) {
	dir := t.TempDir()
	eng, err := New(writeCfg(t, dir))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = eng.Shutdown() })
	// Note: not calling Start.
	eng.OnDNSQuery("example.com", `["1.1.1.1"]`)
	// Gotcha caught if OnDNSQuery panics on nil rt — test would fail.
}

// TestBadConfigRejected is the guard that callers get a clean error on
// missing db_path rather than a nil-deref inside Start.
func TestBadConfigRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
	}{
		{"empty", ""},
		{"not json", "not-json"},
		{"no db_path", `{"snapshot_path":"/tmp/x"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Errorf("expected error for %q", tc.cfg)
			}
		})
	}
}

func hotContains(s publisher.Snapshot, domain string) bool {
	for _, e := range s.Hot {
		if e.Domain == domain {
			return true
		}
	}
	return false
}

func hotEntry(s publisher.Snapshot, domain string) publisher.SnapshotEntry {
	for _, e := range s.Hot {
		if e.Domain == domain {
			return e
		}
	}
	return publisher.SnapshotEntry{}
}

func dumpSnap(s publisher.Snapshot) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "{version:%d hot:[", s.Version)
	for i, e := range s.Hot {
		if i > 0 {
			sb.WriteString(" ")
		}
		fmt.Fprintf(&sb, "%s=%v", e.Domain, e.IPs)
	}
	sb.WriteString("]}")
	return sb.String()
}
