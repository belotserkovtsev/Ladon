package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	return s
}

func TestUpsertDomainCreatesAndBumps(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertDomain(ctx, "example.com", "10.10.0.2", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDomain(ctx, "example.com", "10.10.0.2", time.Time{}); err != nil {
		t.Fatal(err)
	}

	doms, err := s.ListRecentDomains(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(doms) != 1 {
		t.Fatalf("want 1 domain, got %d", len(doms))
	}
	if doms[0].HitCount != 2 {
		t.Fatalf("want hit_count=2, got %d", doms[0].HitCount)
	}
	if doms[0].State != "new" {
		t.Fatalf("want state=new, got %s", doms[0].State)
	}
}

func TestInsertProbeLinksToDomain(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.UpsertDomain(ctx, "example.com", "", time.Time{}); err != nil {
		t.Fatal(err)
	}

	ok := true
	id, err := s.InsertProbe(ctx, ProbeResult{
		Domain:      "example.com",
		DNSOK:       &ok,
		TCPOK:       &ok,
		TLSOK:       &ok,
		ResolvedIPs: []string{"93.184.216.34"},
		LatencyMS:   42,
	}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if id == 0 {
		t.Fatalf("expected non-zero probe id")
	}

	doms, err := s.ListRecentDomains(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if doms[0].LastProbeID == nil || *doms[0].LastProbeID != id {
		t.Fatalf("last_probe_id not linked: %+v", doms[0].LastProbeID)
	}
}
