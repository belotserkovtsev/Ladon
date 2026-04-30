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

// LocalProber runs the built-in TCP:443 + TLS-SNI probe from the current host.
// It's what ladon has shipped with since v0.1.0; the type just wraps the
// existing package-level functions so the engine can accept a Prober interface.
type LocalProber struct {
	Timeout time.Duration
}

// NewLocal returns a LocalProber. A zero timeout falls back to DefaultTimeout.
func NewLocal(timeout time.Duration) *LocalProber {
	return &LocalProber{Timeout: timeout}
}

// Name implements Prober.
func (p *LocalProber) Name() string { return "local" }

// Probe implements Prober. When ips are provided it skips DNS and probes them
// directly (keeps the engine's view consistent with what dnsmasq already gave
// the client); otherwise it falls back to the system resolver.
func (p *LocalProber) Probe(ctx context.Context, domain string, ips []string) Result {
	if len(ips) > 0 {
		return ProbeIPs(ctx, domain, ips, p.Timeout)
	}
	return Probe(ctx, domain, p.Timeout)
}
