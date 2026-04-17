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

// ListProbeCandidates must exclude domains whose exact name or eTLD+1 matches
// a manual deny entry. Without this filter the batch probe worker resurrects
// denied domains into hot_entries after operators prune + ResetOrphanedDomains
// flips their state to 'new' — bypassing the tailer-level deny check.
func TestListProbeCandidatesExcludesDenied(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Seed domains table with several rows in probeable states.
	for _, d := range []string{
		"exact-deny.test",       // exact match with deny entry
		"sub.whole-deny.test",   // matches deny via eTLD+1
		"unrelated.test",        // should remain a candidate
		"noise.allow-only.test", // only on allow list
	} {
		if err := s.UpsertDomain(ctx, d, "", now); err != nil {
			t.Fatalf("upsert %s: %v", d, err)
		}
	}

	_ = s.UpsertManual(ctx, "exact-deny.test", "deny")
	_ = s.UpsertManual(ctx, "whole-deny.test", "deny")
	_ = s.UpsertManual(ctx, "noise.allow-only.test", "allow")

	cands, err := s.ListProbeCandidates(ctx, 100, now)
	if err != nil {
		t.Fatalf("ListProbeCandidates: %v", err)
	}

	seen := map[string]bool{}
	for _, c := range cands {
		seen[c.Domain] = true
	}

	if seen["exact-deny.test"] {
		t.Error("exact-deny.test must not be a candidate (exact deny match)")
	}
	if seen["sub.whole-deny.test"] {
		t.Error("sub.whole-deny.test must not be a candidate (eTLD+1 deny match)")
	}
	if !seen["unrelated.test"] {
		t.Error("unrelated.test should be a candidate (not on any list)")
	}
	if !seen["noise.allow-only.test"] {
		t.Error("noise.allow-only.test should be a candidate (allow list doesn't block probing)")
	}
}

// ListProbeCandidates must keep excluding a domain even when only its eTLD+1
// is in the deny list — this is the operator's way of saying "whole family".
func TestListProbeCandidatesETLDFamilyDeny(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_ = s.UpsertDomain(ctx, "a.family.test", "", now)
	_ = s.UpsertDomain(ctx, "b.family.test", "", now)
	_ = s.UpsertDomain(ctx, "other.test", "", now)
	_ = s.UpsertManual(ctx, "family.test", "deny")

	cands, err := s.ListProbeCandidates(ctx, 100, now)
	if err != nil {
		t.Fatalf("ListProbeCandidates: %v", err)
	}
	seen := map[string]bool{}
	for _, c := range cands {
		seen[c.Domain] = true
	}
	if seen["a.family.test"] || seen["b.family.test"] {
		t.Errorf("family subdomains must be excluded when family.test is in deny, got %v", seen)
	}
	if !seen["other.test"] {
		t.Errorf("other.test must remain a candidate")
	}
}

// DeleteDeniedDomains removes any domains row whose exact name or eTLD+1 is in
// the deny list. Covers the cleanup path invoked during `ladon prune`.
func TestDeleteDeniedDomains(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	_ = s.UpsertDomain(ctx, "exact.deny", "", now)
	_ = s.UpsertDomain(ctx, "sub.fam.deny", "", now) // etld+1 = fam.deny
	_ = s.UpsertDomain(ctx, "keeper.test", "", now)

	_ = s.UpsertManual(ctx, "exact.deny", "deny")
	_ = s.UpsertManual(ctx, "fam.deny", "deny")
	_ = s.UpsertManual(ctx, "keeper.test", "allow") // allow must not trigger deletion

	n, err := s.DeleteDeniedDomains(ctx)
	if err != nil {
		t.Fatalf("DeleteDeniedDomains: %v", err)
	}
	if n != 2 {
		t.Errorf("deleted = %d, want 2 (exact.deny + sub.fam.deny)", n)
	}

	// Verify only keeper.test remains.
	var surviving int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM domains`).Scan(&surviving); err != nil {
		t.Fatal(err)
	}
	if surviving != 1 {
		t.Errorf("surviving rows = %d, want 1 (keeper.test)", surviving)
	}

	// Idempotent: second call deletes nothing.
	if n2, err := s.DeleteDeniedDomains(ctx); err != nil {
		t.Fatal(err)
	} else if n2 != 0 {
		t.Errorf("second call deleted %d, want 0", n2)
	}
}

// Regression test for the bug that motivated v0.4.1: operator adds a domain to
// deny, runs prune, and expects no re-hydration. Before the fix,
// ResetOrphanedDomains flipped denied rows to 'new' and ListProbeCandidates
// returned them, so the batch probe worker would resurrect them on the next
// tick.
func TestPruneDoesNotResurrectDenied(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Seed: denied.test is in hot and cache (as if previously probed), plain.test
	// is the control row that should behave as before.
	_ = s.UpsertDomain(ctx, "denied.test", "", now)
	_ = s.UpsertDomain(ctx, "plain.test", "", now)
	_ = s.UpsertHotEntry(ctx, "denied.test", "old verdict", now.Add(24*time.Hour))
	_ = s.PromoteCache(ctx, "denied.test", "repeated_fail", now)
	_ = s.UpsertHotEntry(ctx, "plain.test", "old verdict", now.Add(24*time.Hour))

	// Operator adds the deny entry after the fact.
	_ = s.UpsertManual(ctx, "denied.test", "deny")

	// Simulate `ladon prune -hot -cache`: clear hot/cache, scrub denied, reset orphans.
	if _, err := s.PruneHot(ctx, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PruneCache(ctx, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteDeniedDomains(ctx); err != nil {
		t.Fatal(err)
	} else if n != 1 {
		t.Errorf("expected 1 denied row deleted, got %d", n)
	}
	if _, err := s.ResetOrphanedDomains(ctx); err != nil {
		t.Fatal(err)
	}

	// denied.test must not be in the probe candidate list — row is gone AND
	// filter catches it even if the row survives.
	cands, err := s.ListProbeCandidates(ctx, 100, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cands {
		if c.Domain == "denied.test" {
			t.Fatal("denied.test must not be a probe candidate after prune")
		}
	}
	// plain.test should still be a candidate (it was reset to 'new' by ResetOrphanedDomains).
	found := false
	for _, c := range cands {
		if c.Domain == "plain.test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("plain.test should still be a candidate (reset to 'new' after prune)")
	}
}
