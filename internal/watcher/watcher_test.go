package watcher

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

func newStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	return s
}

func TestIngestNormalizesAndPersists(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	cases := []struct {
		in         string
		wantDomain string
	}{
		{"example.com", "example.com"},
		{"Example.COM", "example.com"},
		{"example.com.", "example.com"},           // trailing dot stripped
		{"  padded.test  ", "padded.test"},        // whitespace
		{"SUB.Example.COM.", "sub.example.com"},   // combined
	}

	for _, tc := range cases {
		obs, err := Ingest(ctx, s, Event{Domain: tc.in, Peer: "10.10.0.2"})
		if err != nil {
			t.Fatalf("Ingest(%q): %v", tc.in, err)
		}
		if obs == nil {
			t.Fatalf("Ingest(%q) returned nil observation", tc.in)
		}
		if obs.Domain != tc.wantDomain {
			t.Errorf("Ingest(%q).Domain = %q; want %q", tc.in, obs.Domain, tc.wantDomain)
		}
	}

	// Verify persistence: each normalized form hit the DB.
	doms, err := s.ListRecentDomains(ctx, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	seen := map[string]bool{}
	for _, d := range doms {
		seen[d.Domain] = true
	}
	for _, want := range []string{"example.com", "padded.test", "sub.example.com"} {
		if !seen[want] {
			t.Errorf("expected domain %q in storage, not found", want)
		}
	}
}

func TestIngestSkipsEmptyDomain(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	cases := []string{"", "   ", ".", "   .   "}
	for _, in := range cases {
		obs, err := Ingest(ctx, s, Event{Domain: in, Peer: "10.10.0.2"})
		if err != nil {
			t.Errorf("Ingest(%q): unexpected error %v", in, err)
		}
		if obs != nil {
			t.Errorf("Ingest(%q) should have returned nil observation, got %+v", in, obs)
		}
	}
	// Nothing should have been persisted.
	doms, _ := s.ListRecentDomains(ctx, 10)
	if len(doms) != 0 {
		t.Errorf("empty domains leaked into storage: %+v", doms)
	}
}
