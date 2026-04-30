package prober

import (
	"context"
	"time"
)

// Prober is the interface the engine uses to decide whether a domain is
// reachable. Implementations can probe locally (TCP/TLS from this host) or
// defer to a remote service — see LocalProber and RemoteProber.
type Prober interface {
	// Probe classifies the domain. When ips is non-empty the implementation
	// should use those addresses directly; when empty it may resolve DNS itself
	// (LocalProber does; RemoteProber delegates to the remote server).
	Probe(ctx context.Context, domain string, ips []string) Result

	// Name identifies the backend in logs and metrics.
	Name() string
}

// LocalProber runs the built-in DNS / TCP:443 / TLS-SNI / HTTP probe
// pipeline from the current host. The Fingerprint field selects which
// browser ClientHello uTLS will mimic at the TLS stage — see
// fingerprints.go for the supported set. Empty Fingerprint falls back to
// DefaultFingerprint.
type LocalProber struct {
	Timeout     time.Duration
	Fingerprint Fingerprint
}

// NewLocal returns a LocalProber. A zero timeout falls back to
// DefaultTimeout; an empty fingerprint to DefaultFingerprint.
func NewLocal(timeout time.Duration, fp Fingerprint) *LocalProber {
	return &LocalProber{Timeout: timeout, Fingerprint: fp}
}

// Name implements Prober.
func (p *LocalProber) Name() string { return "local" }

// Probe implements Prober. When ips are provided it skips DNS and probes them
// directly (keeps the engine's view consistent with what dnsmasq already gave
// the client); otherwise it falls back to the system resolver.
func (p *LocalProber) Probe(ctx context.Context, domain string, ips []string) Result {
	fp := p.Fingerprint
	if fp == "" {
		fp = DefaultFingerprint
	}
	if len(ips) > 0 {
		return ProbeIPsWithFingerprint(ctx, domain, ips, fp, p.Timeout)
	}
	return ProbeWithFingerprint(ctx, domain, fp, p.Timeout)
}
