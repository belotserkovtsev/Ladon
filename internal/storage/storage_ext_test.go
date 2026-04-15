package storage

import (
	"context"
	"testing"
	"time"
)

func TestProbeEligible(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("unknown domain — eligible", func(t *testing.T) {
		ok, err := s.ProbeEligible(ctx, "never.seen", now)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("unknown domain should be eligible so first inline probe can fire")
		}
	})

	t.Run("state=new, no cooldown", func(t *testing.T) {
		_ = s.UpsertDomain(ctx, "fresh.test", "", now)
		ok, _ := s.ProbeEligible(ctx, "fresh.test", now)
		if !ok {
			t.Fatal("new with null cooldown must be eligible")
		}
	})

	t.Run("state=hot, cooldown expired", func(t *testing.T) {
		_ = s.UpsertDomain(ctx, "hot-expired.test", "", now)
		_ = s.SetDomainState(ctx, "hot-expired.test", "hot", now.Add(-time.Minute))
		ok, _ := s.ProbeEligible(ctx, "hot-expired.test", now)
		if !ok {
			t.Fatal("hot with expired cooldown must be eligible")
		}
	})

	t.Run("state=hot, cooldown active", func(t *testing.T) {
		_ = s.UpsertDomain(ctx, "hot-cooling.test", "", now)
		_ = s.SetDomainState(ctx, "hot-cooling.test", "hot", now.Add(5*time.Minute))
		ok, _ := s.ProbeEligible(ctx, "hot-cooling.test", now)
		if ok {
			t.Fatal("hot with future cooldown must NOT be eligible")
		}
	})

	t.Run("state=ignore → not eligible", func(t *testing.T) {
		_ = s.UpsertDomain(ctx, "boring.test", "", now)
		_ = s.SetDomainState(ctx, "boring.test", "ignore", time.Time{})
		ok, _ := s.ProbeEligible(ctx, "boring.test", now)
		if ok {
			t.Fatal("ignore state must not be eligible")
		}
	})

	t.Run("state=cache → not eligible", func(t *testing.T) {
		_ = s.UpsertDomain(ctx, "permanent.test", "", now)
		_ = s.PromoteCache(ctx, "permanent.test", "test", now)
		ok, _ := s.ProbeEligible(ctx, "permanent.test", now)
		if ok {
			t.Fatal("cache state must not be re-probed by inline path")
		}
	})
}

func TestLookupIPsByETLD(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Seed two siblings under fbcdn.net and one under unrelated.com.
	_ = s.UpsertDomain(ctx, "aaa.fbcdn.net", "", now)
	_ = s.UpsertDomain(ctx, "bbb.fbcdn.net", "", now)
	_ = s.UpsertDomain(ctx, "hello.unrelated.com", "", now)

	_ = s.UpsertDNSObservation(ctx, "aaa.fbcdn.net", "1.1.1.1", now)
	_ = s.UpsertDNSObservation(ctx, "aaa.fbcdn.net", "1.1.1.2", now)
	_ = s.UpsertDNSObservation(ctx, "bbb.fbcdn.net", "1.1.1.2", now) // shared IP → dedup
	_ = s.UpsertDNSObservation(ctx, "bbb.fbcdn.net", "1.1.1.3", now)
	_ = s.UpsertDNSObservation(ctx, "hello.unrelated.com", "9.9.9.9", now)

	ips, err := s.LookupIPsByETLD(ctx, "fbcdn.net", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, ip := range ips {
		seen[ip] = true
	}
	for _, want := range []string{"1.1.1.1", "1.1.1.2", "1.1.1.3"} {
		if !seen[want] {
			t.Errorf("expected %s in fbcdn.net IPs, got %v", want, ips)
		}
	}
	if seen["9.9.9.9"] {
		t.Errorf("leak: unrelated.com IP appeared under fbcdn.net: %v", ips)
	}
	if len(ips) != 3 {
		t.Errorf("expected 3 distinct IPs, got %d: %v", len(ips), ips)
	}
}

func TestIsInDenyList(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_ = s.UpsertManual(ctx, "exact.test", "deny")
	_ = s.UpsertManual(ctx, "wholefamily.com", "deny")
	_ = s.UpsertManual(ctx, "noise.allow", "allow") // should not match

	cases := []struct {
		domain string
		etld   string
		want   bool
	}{
		{"exact.test", "exact.test", true},
		{"sub.wholefamily.com", "wholefamily.com", true}, // matches via eTLD+1
		{"unrelated.com", "unrelated.com", false},
		{"noise.allow", "noise.allow", false}, // allow list is not deny
	}
	for _, tc := range cases {
		got, err := s.IsInDenyList(ctx, tc.domain, tc.etld)
		if err != nil {
			t.Fatalf("IsInDenyList(%s): %v", tc.domain, err)
		}
		if got != tc.want {
			t.Errorf("IsInDenyList(%s, %s) = %v; want %v", tc.domain, tc.etld, got, tc.want)
		}
	}
}

func TestCountFailingProbes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	ok, fail := true, false
	// Three fails, two successes for same domain; one old fail outside window.
	_ = s.UpsertDomain(ctx, "example.test", "", now)
	insert := func(dns, tcp, tls *bool, at time.Time) {
		if _, err := s.InsertProbe(ctx, ProbeResult{
			Domain: "example.test",
			DNSOK:  dns, TCPOK: tcp, TLSOK: tls,
		}, at); err != nil {
			t.Fatal(err)
		}
	}
	insert(&ok, &fail, &fail, now.Add(-10*time.Minute))
	insert(&ok, &fail, &fail, now.Add(-20*time.Minute))
	insert(&ok, &fail, &fail, now.Add(-30*time.Minute))
	insert(&ok, &ok, &ok, now.Add(-40*time.Minute))   // success, not counted
	insert(&ok, &ok, &ok, now.Add(-50*time.Minute))   // success
	insert(&ok, &fail, &fail, now.Add(-48*time.Hour)) // old fail, outside window

	n, err := s.CountFailingProbes(ctx, "example.test", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("want 3 failing probes in last hour, got %d", n)
	}
}
