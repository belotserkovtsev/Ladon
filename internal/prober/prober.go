// Package prober runs staged network probes (DNS / TCP:443 / TLS-SNI) against a domain.
package prober

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// Result holds the outcome of a staged probe.
type Result struct {
	Domain        string
	DNSOK         bool
	TCPOK         bool
	TLSOK         bool
	HTTPOK        *bool // reserved for future HTTP probe
	ResolvedIPs   []string
	FailureReason string
	LatencyMS     int
}

const (
	DefaultTimeout = 2 * time.Second
	MaxIPsToTry    = 3
)

// Probe runs DNS → TCP:443 → TLS-SNI against domain, short-circuiting on failure.
// Uses the system resolver; subject to whatever /etc/resolv.conf points at.
// Prefer ProbeIPs when the caller already knows what the client resolved to —
// keeps the engine's view consistent with the client's.
func Probe(ctx context.Context, domain string, timeout time.Duration) Result {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	started := time.Now()
	r := Result{Domain: domain}

	resolver := &net.Resolver{}
	addrs, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		r.FailureReason = "dns:" + err.Error()
		r.LatencyMS = int(time.Since(started) / time.Millisecond)
		return r
	}
	seen := map[string]struct{}{}
	for _, a := range addrs {
		s := a.IP.String()
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		r.ResolvedIPs = append(r.ResolvedIPs, s)
	}
	return probeTCPTLS(ctx, r, started, timeout)
}

// ProbeIPs runs TCP:443 → TLS-SNI against a caller-supplied IP list.
// Used when the client's resolver already gave us the answers (via dns_cache) —
// avoids a redundant DNS lookup that might disagree with the client's view.
func ProbeIPs(ctx context.Context, domain string, ips []string, timeout time.Duration) Result {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	started := time.Now()
	r := Result{Domain: domain, ResolvedIPs: ips}
	if len(ips) == 0 {
		r.FailureReason = "no_ips"
		r.LatencyMS = int(time.Since(started) / time.Millisecond)
		return r
	}
	return probeTCPTLS(ctx, r, started, timeout)
}

// probeTCPTLS assumes r.ResolvedIPs is populated (or empty → treat as DNS fail).
func probeTCPTLS(ctx context.Context, r Result, started time.Time, timeout time.Duration) Result {
	r.DNSOK = len(r.ResolvedIPs) > 0
	if !r.DNSOK {
		r.FailureReason = "no_ips"
		r.LatencyMS = int(time.Since(started) / time.Millisecond)
		return r
	}

	dialer := net.Dialer{Timeout: timeout}
	var reachable string
	for i, ip := range r.ResolvedIPs {
		if i >= MaxIPsToTry {
			break
		}
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
		if err != nil {
			continue
		}
		conn.Close()
		reachable = ip
		r.TCPOK = true
		break
	}
	if !r.TCPOK {
		r.FailureReason = "tcp_connect_failed"
		r.LatencyMS = int(time.Since(started) / time.Millisecond)
		return r
	}

	// We probe TLS for *reachability*, not trust: the ultimate consumer is the
	// user's device (which may trust CAs we don't, e.g. Russian Mincifry CA).
	// Cert validity is not the engine's concern — connect + handshake bytes is.
	tlsConn, err := tls.DialWithDialer(&dialer, "tcp", net.JoinHostPort(reachable, "443"), &tls.Config{
		ServerName:         r.Domain,
		InsecureSkipVerify: true, // #nosec G402 — intentional, see comment above
	})
	if err != nil {
		r.FailureReason = "tls:" + err.Error()
	} else {
		tlsConn.Close()
		r.TLSOK = true
	}

	r.LatencyMS = int(time.Since(started) / time.Millisecond)
	return r
}

// ErrNoDomain signals an empty input.
var ErrNoDomain = errors.New("empty domain")

// Validate is a tiny sanity check for CLI input.
func Validate(domain string) error {
	if domain == "" {
		return ErrNoDomain
	}
	if !isValidDomain(domain) {
		return fmt.Errorf("invalid domain: %q", domain)
	}
	return nil
}

func isValidDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	for _, r := range d {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}
