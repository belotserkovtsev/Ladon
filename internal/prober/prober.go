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
//
// FailureCode is a stable enum suitable for engine branching and grep; it
// also forms the prefix of FailureReason ("<code>: <raw err>"). Old call
// sites that only read FailureReason keep working unchanged.
type Result struct {
	Domain        string
	DNSOK         bool
	TCPOK         bool
	TLSOK         bool
	TLS12OK       *bool // populated when the 1.2-restricted retry runs
	TLS13OK       *bool // populated by the unrestricted attempt
	HTTPOK        *bool
	ResolvedIPs   []string
	FailureCode   FailureCode
	FailureReason string
	LatencyMS     int
}

// IsRemoteTransportFailure reports whether this result represents the
// remote prober itself being unreachable rather than a verdict about the
// target. Engine treats those as Hot (safe default) but suppresses
// noise-floor signals the caller would otherwise count as real DPI.
func (r Result) IsRemoteTransportFailure() bool {
	return r.FailureCode == CodeRemote
}

const (
	DefaultTimeout = 1500 * time.Millisecond
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
		r.FailureCode = categorize(stageDNS, err)
		r.FailureReason = formatReason(r.FailureCode, err)
		r.LatencyMS = int(time.Since(started) / time.Millisecond)
		return r
	}
	seen := map[string]struct{}{}
	for _, a := range addrs {
		// v4-only: gateway routing, stun0 and prod ipset are all v4.
		if a.IP.To4() == nil {
			continue
		}
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
		r.FailureCode = CodeNoIPs
		r.FailureReason = string(CodeNoIPs)
		r.LatencyMS = int(time.Since(started) / time.Millisecond)
		return r
	}
	return probeTCPTLS(ctx, r, started, timeout)
}

// probeTCPTLS races TCP:443 connects across up to MaxIPsToTry IPs in parallel,
// takes the first success, then runs TLS-SNI on that IP. Losing dials are
// cancelled via the shared context. Compared to the sequential loop this
// collapses worst-case latency from sum(timeouts) to max(timeouts).
func probeTCPTLS(ctx context.Context, r Result, started time.Time, timeout time.Duration) Result {
	r.DNSOK = len(r.ResolvedIPs) > 0
	if !r.DNSOK {
		r.FailureCode = CodeNoIPs
		r.FailureReason = string(CodeNoIPs)
		r.LatencyMS = int(time.Since(started) / time.Millisecond)
		return r
	}

	targets := r.ResolvedIPs
	if len(targets) > MaxIPsToTry {
		targets = targets[:MaxIPsToTry]
	}

	dialer := net.Dialer{Timeout: timeout}
	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type dialResult struct {
		ip  string
		err error
	}
	out := make(chan dialResult, len(targets))

	for _, ip := range targets {
		go func(ip string) {
			conn, err := dialer.DialContext(dialCtx, "tcp", net.JoinHostPort(ip, "443"))
			if err == nil {
				conn.Close()
			}
			out <- dialResult{ip: ip, err: err}
		}(ip)
	}

	var reachable string
	var lastErr error
	for i := 0; i < len(targets); i++ {
		res := <-out
		if res.err == nil && reachable == "" {
			reachable = res.ip
			cancel() // let the other dials unwind
			break
		}
		if res.err != nil {
			lastErr = res.err
		}
	}
	if reachable == "" {
		if lastErr != nil {
			r.FailureCode = categorize(stageTCP, lastErr)
			r.FailureReason = formatReason(r.FailureCode, lastErr)
		} else {
			r.FailureCode = CodeTCPError
			r.FailureReason = "tcp_connect_failed"
		}
		r.LatencyMS = int(time.Since(started) / time.Millisecond)
		return r
	}
	r.TCPOK = true

	probeTLSStaged(&r, reachable, "443", timeout)
	r.LatencyMS = int(time.Since(started) / time.Millisecond)
	return r
}

// probeTLSStaged runs the TLS-SNI handshake first unrestricted (Go picks the
// highest mutually-supported version, which is 1.3 against any modern
// server) and, if that fails, retries pinned to TLS 1.2. The split is the
// primary signal we use to detect ClientHello-targeted DPI: when 1.3 fails
// but 1.2 succeeds, the middlebox is almost certainly inspecting the
// ClientHello (ECH/ESNI / cipher-suite fingerprinting).
//
// The retry only fires on TLS-stage failures — a clean 1.3 handshake leaves
// TLS12OK nil (we don't burn an extra dial just to populate the field).
//
// We do NOT mark TLSOK=false when 1.3 fails / 1.2 ok in this function — the
// fallback succeeded, the connection is reachable. The tls13_block verdict
// is layered on top in a later phase, where it can interact with the HTTP
// probe and decision rules.
func probeTLSStaged(r *Result, ip, port string, timeout time.Duration) {
	ok, code, reason, version := tlsHandshake(ip, port, r.Domain, timeout, 0)
	if ok {
		r.TLSOK = true
		recordTLSVersion(r, version)
		return
	}
	// 1.3 (or whatever the unrestricted attempt picked) failed. Stash the
	// error so it survives if the 1.2 retry also fails.
	r.FailureCode = code
	r.FailureReason = reason
	f := false
	r.TLS13OK = &f

	// 1.2-only retry. New TCP connection — TLS failure usually drops the
	// underlying socket too. We already paid for one failed handshake so
	// this can stretch latency, but it's the price of distinguishing
	// "real block" from "1.3-only block".
	if ok2, _, _, _ := tlsHandshake(ip, port, r.Domain, timeout, tls.VersionTLS12); ok2 {
		t := true
		r.TLS12OK = &t
		r.TLSOK = true
		// Clear the failure carried over from the 1.3 attempt — TLS as a
		// whole succeeded. TLS13OK=false stays so the asymmetry is visible
		// to the next phase (which will lift it to a tls13_block verdict).
		r.FailureCode = CodeOK
		r.FailureReason = ""
		return
	}
	r.TLS12OK = &f
}

// tlsHandshake runs one TLS dial. maxVersion=0 means "unrestricted" (Go
// negotiates whatever it can). Returns the negotiated protocol version on
// success so the caller can record TLS12OK vs TLS13OK accurately.
func tlsHandshake(ip, port, sni string, timeout time.Duration, maxVersion uint16) (ok bool, code FailureCode, reason string, version uint16) {
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // #nosec G402 — we're probing reachability, not verifying identity
	}
	if maxVersion != 0 {
		cfg.MaxVersion = maxVersion
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout},
		"tcp", net.JoinHostPort(ip, port), cfg)
	if err != nil {
		c := categorize(stageTLS, err)
		return false, c, formatReason(c, err), 0
	}
	state := conn.ConnectionState()
	conn.Close()
	return true, CodeOK, "", state.Version
}

// recordTLSVersion sets TLS12OK or TLS13OK based on the negotiated version.
// Called only on a successful handshake. Servers that only support 1.2
// will end up with TLS12OK=ptr(true), TLS13OK=nil (we never tried 1.3
// directly because the unrestricted dial already settled at 1.2).
func recordTLSVersion(r *Result, version uint16) {
	t := true
	switch version {
	case tls.VersionTLS13:
		r.TLS13OK = &t
	case tls.VersionTLS12:
		r.TLS12OK = &t
	}
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
