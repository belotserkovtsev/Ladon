package publisher

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

func newTestStore(t *testing.T) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "snap.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	return s
}

// TestSnapshotEmpty checks the empty-state shape: version + timestamp, no
// entries. Consumers should be able to parse an empty snapshot without
// nil-panicking on the slices.
func TestSnapshotEmpty(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "hot-snapshot.json")

	if err := PublishSnapshotJSON(ctx, s, out, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	var snap Snapshot
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snap.Version != SnapshotVersion {
		t.Errorf("version = %d, want %d", snap.Version, SnapshotVersion)
	}
	if len(snap.Hot) != 0 || len(snap.Cache) != 0 || len(snap.ManualDeny) != 0 {
		t.Errorf("expected all lists empty, got hot=%d cache=%d deny=%d",
			len(snap.Hot), len(snap.Cache), len(snap.ManualDeny))
	}
}

// TestSnapshotHotWithIPs seeds a hot entry plus fresh dns_cache rows and
// verifies both the domain and its IPs land in the snapshot.
func TestSnapshotHotWithIPs(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().UTC()

	if err := s.UpsertDomain(ctx, "blocked.test", "10.10.0.2", now); err != nil {
		t.Fatalf("upsert domain: %v", err)
	}
	if err := s.UpsertHotEntry(ctx, "blocked.test", "tcp_timeout", now.Add(24*time.Hour)); err != nil {
		t.Fatalf("upsert hot: %v", err)
	}
	for _, ip := range []string{"1.1.1.1", "2.2.2.2"} {
		if err := s.UpsertDNSObservation(ctx, "blocked.test", ip, now); err != nil {
			t.Fatalf("upsert dns %s: %v", ip, err)
		}
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "hot-snapshot.json")
	if err := PublishSnapshotJSON(ctx, s, out, now.Add(-time.Hour)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	var snap Snapshot
	data, _ := os.ReadFile(out)
	if err := json.Unmarshal(data, &snap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(snap.Hot) != 1 {
		t.Fatalf("hot entries = %d, want 1 (%+v)", len(snap.Hot), snap.Hot)
	}
	if snap.Hot[0].Domain != "blocked.test" {
		t.Errorf("hot domain = %q, want blocked.test", snap.Hot[0].Domain)
	}
	gotIPs := map[string]bool{}
	for _, ip := range snap.Hot[0].IPs {
		gotIPs[ip] = true
	}
	if !gotIPs["1.1.1.1"] || !gotIPs["2.2.2.2"] {
		t.Errorf("IPs = %v, want both 1.1.1.1 and 2.2.2.2", snap.Hot[0].IPs)
	}
}

// TestSnapshotFreshnessCap verifies that stale dns_cache observations are
// excluded — a consumer should never route to an IP that rotated away from
// the domain some time ago.
func TestSnapshotFreshnessCap(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	now := time.Now().UTC()

	if err := s.UpsertDomain(ctx, "blocked.test", "10.10.0.2", now); err != nil {
		t.Fatalf("upsert domain: %v", err)
	}
	if err := s.UpsertHotEntry(ctx, "blocked.test", "tcp_timeout", now.Add(24*time.Hour)); err != nil {
		t.Fatalf("upsert hot: %v", err)
	}
	// Stale observation from 2h ago — must be filtered out when freshSince=1h ago.
	if err := s.UpsertDNSObservation(ctx, "blocked.test", "9.9.9.9", now.Add(-2*time.Hour)); err != nil {
		t.Fatalf("upsert dns: %v", err)
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "hot-snapshot.json")
	if err := PublishSnapshotJSON(ctx, s, out, now.Add(-time.Hour)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	var snap Snapshot
	data, _ := os.ReadFile(out)
	_ = json.Unmarshal(data, &snap)
	if len(snap.Hot) != 1 {
		t.Fatalf("hot = %d, want 1", len(snap.Hot))
	}
	if len(snap.Hot[0].IPs) != 0 {
		t.Errorf("IPs = %v, want empty (all stale)", snap.Hot[0].IPs)
	}
}

// TestSnapshotManualDeny checks that manual-deny entries surface in the
// dedicated section — iOS consumer uses them to short-circuit routing
// without waiting for a probe.
func TestSnapshotManualDeny(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	if err := s.UpsertManual(ctx, "gosuslugi.ru", "deny"); err != nil {
		t.Fatalf("upsert manual: %v", err)
	}

	dir := t.TempDir()
	out := filepath.Join(dir, "hot-snapshot.json")
	if err := PublishSnapshotJSON(ctx, s, out, time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("publish: %v", err)
	}

	var snap Snapshot
	data, _ := os.ReadFile(out)
	_ = json.Unmarshal(data, &snap)
	if len(snap.ManualDeny) != 1 || snap.ManualDeny[0].Domain != "gosuslugi.ru" {
		t.Errorf("manual_deny = %+v, want gosuslugi.ru", snap.ManualDeny)
	}
}

// TestSnapshotAtomicRename verifies tmp+rename pattern leaves no orphan
// files and produces a valid JSON at the target path.
func TestSnapshotAtomicRename(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	dir := t.TempDir()
	out := filepath.Join(dir, "hot-snapshot.json")

	for i := 0; i < 5; i++ {
		if err := PublishSnapshotJSON(ctx, s, out, time.Now().Add(-time.Hour)); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	// Only the target file should remain; no ".snapshot-*.tmp" leftovers.
	if len(entries) != 1 || entries[0].Name() != "hot-snapshot.json" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("unexpected leftover files: %v", names)
	}
}
