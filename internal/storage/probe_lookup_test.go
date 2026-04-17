package storage

import (
	"context"
	"testing"
	"time"
)

func TestLatestProbeOK_NoProbe(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	ok, exists, err := s.LatestProbeOK(ctx, "never-probed.test", "tcp+tls")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Errorf("exists = true, want false for un-probed domain")
	}
	if ok {
		t.Errorf("ok = true on absent probe")
	}
}

func TestLatestProbeOK_ReturnsLatestBySameProto(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	tf, tt := false, true

	// Older fail, newer success — we expect "ok=true" (latest wins).
	if _, err := s.InsertProbe(ctx, ProbeResult{
		Domain: "mixed.test", Proto: "tcp+tls",
		TCPOK: &tf, TLSOK: &tf,
	}, time.Now().UTC().Add(-1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertProbe(ctx, ProbeResult{
		Domain: "mixed.test", Proto: "tcp+tls",
		TCPOK: &tt, TLSOK: &tt,
	}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	ok, exists, err := s.LatestProbeOK(ctx, "mixed.test", "tcp+tls")
	if err != nil {
		t.Fatal(err)
	}
	if !exists || !ok {
		t.Errorf("latest row was success; got exists=%v ok=%v", exists, ok)
	}
}

func TestLatestProbeOK_SeparatesByProto(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	tt, ff := true, false

	// TCP success, QUIC fail — proto-specific queries should disagree.
	s.InsertProbe(ctx, ProbeResult{Domain: "split.test", Proto: "tcp+tls", TCPOK: &tt, TLSOK: &tt}, time.Now().UTC())
	s.InsertProbe(ctx, ProbeResult{Domain: "split.test", Proto: "quic", TCPOK: &ff, TLSOK: &ff}, time.Now().UTC())

	tcpOK, _, _ := s.LatestProbeOK(ctx, "split.test", "tcp+tls")
	quicOK, _, _ := s.LatestProbeOK(ctx, "split.test", "quic")
	if !tcpOK {
		t.Errorf("tcp+tls should be OK")
	}
	if quicOK {
		t.Errorf("quic should NOT be OK")
	}
}

func TestDomainHasUDPFlows_RequiresRecentUDPToJoinedIP(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	now := time.Now().UTC()

	// Domain known to DNS cache; LAN client hits one of its IPs via UDP.
	s.UpsertDNSObservation(ctx, "udp.test", "1.1.1.1", now)
	s.InsertObservedFlow(ctx, "1.1.1.1", "udp", 443, "192.168.0.10", now)

	has, err := s.DomainHasUDPFlows(ctx, "udp.test", now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Errorf("UDP flow to domain's IP should register")
	}

	// TCP-only domain — no UDP evidence.
	s.UpsertDNSObservation(ctx, "tcp-only.test", "2.2.2.2", now)
	s.InsertObservedFlow(ctx, "2.2.2.2", "tcp", 443, "192.168.0.10", now)
	has, _ = s.DomainHasUDPFlows(ctx, "tcp-only.test", now.Add(-time.Hour))
	if has {
		t.Errorf("TCP-only domain incorrectly reported as UDP-observed")
	}

	// UDP flow too old for the window — should be filtered out.
	has, _ = s.DomainHasUDPFlows(ctx, "udp.test", now.Add(time.Hour))
	if has {
		t.Errorf("stale UDP flow should fall outside window")
	}
}
