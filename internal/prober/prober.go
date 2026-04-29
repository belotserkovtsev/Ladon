// Package prober runs staged network probes (DNS / TCP:443 / TLS-SNI / HTTP) against a domain.
package prober

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// httpReadLimit caps how many response bytes the HTTP cutoff probe will
// consume. Picked to comfortably exceed the ~14-34KB window where some
// RU-DPI deployments terminate CDN/hosting connections (the dpi-detector
// project documents this signature). If we successfully read this much,
// the path is "deep enough" to consider not-cut.
const httpReadLimit = 32 * 1024

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

	conn := probeTLSStaged(&r, reachable, "443", timeout)
	if conn != nil {
		probeHTTPStaged(&r, conn, timeout)
		conn.Close()
	}
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
// probeTLSStaged returns a live *tls.Conn on success so the caller can
// keep probing on the same connection (HTTP cutoff detection). Caller must
// close the conn. Returns nil when both 1.3 and 1.2 attempts fail.
func probeTLSStaged(r *Result, ip, port string, timeout time.Duration) *tls.Conn {
	conn, code, reason, version := tlsHandshake(ip, port, r.Domain, timeout, 0)
	if conn != nil {
		r.TLSOK = true
		recordTLSVersion(r, version)
		return conn
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
	conn2, _, _, _ := tlsHandshake(ip, port, r.Domain, timeout, tls.VersionTLS12)
	if conn2 != nil {
		t := true
		r.TLS12OK = &t
		r.TLSOK = true
		// Clear the failure carried over from the 1.3 attempt — TLS as a
		// whole succeeded. TLS13OK=false stays so the asymmetry is visible
		// to the next phase (which will lift it to a tls13_block verdict).
		r.FailureCode = CodeOK
		r.FailureReason = ""
		return conn2
	}
	r.TLS12OK = &f
	return nil
}

// tlsHandshake runs one TLS dial. maxVersion=0 means "unrestricted" (Go
// negotiates whatever it can). Returns the live conn on success so the
// caller can run further stages (HTTP probe) without a fresh dial.
func tlsHandshake(ip, port, sni string, timeout time.Duration, maxVersion uint16) (conn *tls.Conn, code FailureCode, reason string, version uint16) {
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // #nosec G402 — we're probing reachability, not verifying identity
	}
	if maxVersion != 0 {
		cfg.MaxVersion = maxVersion
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout},
		"tcp", net.JoinHostPort(ip, port), cfg)
	if err != nil {
		code := categorize(stageTLS, err)
		return nil, code, formatReason(code, err), 0
	}
	state := c.ConnectionState()
	return c, CodeOK, "", state.Version
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

// probeHTTPStaged sends a minimal GET on a live TLS conn and tries to
// consume up to httpReadLimit bytes of the response. It catches the
// "TLS handshake fine, but DPI cuts the actual stream after N KB" pattern
// that classifies linkedin.com / instagram.com / rutracker.org under
// existing TCP+TLS-only probing — the L7-blindspot we want to close.
//
// HTTPOK is a tri-state: nil if we didn't run the stage (caller skipped),
// ptr(true) if a complete response (any status) was parsed, ptr(false)
// otherwise. A 4xx/5xx with a tiny body still counts as ptr(true) — the
// path is reachable; the server made a deliberate response. We're
// detecting middlebox cutoffs, not server semantics.
func probeHTTPStaged(r *Result, conn *tls.Conn, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		setHTTPFail(r, stageHTTP, err)
		return
	}

	req := fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (compatible; ladon-probe)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		r.Domain,
	)
	if _, err := io.WriteString(conn, req); err != nil {
		setHTTPFail(r, stageHTTP, err)
		return
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		// Headers never completed — DPI most often cuts here, before the
		// server even gets a chance to respond. Categorize as cutoff.
		setHTTPFail(r, stageHTTP, err)
		return
	}

	// Drain up to the limit. Many small responses finish well below it
	// (e.g. an empty 204 or a 301 redirect) — that's fine, EOF after a
	// clean response is success. We only fail on read errors that
	// indicate the stream was severed mid-flight.
	_, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, httpReadLimit))
	resp.Body.Close()
	if copyErr != nil && !errors.Is(copyErr, io.EOF) {
		setHTTPFail(r, stageHTTP, copyErr)
		return
	}

	t := true
	r.HTTPOK = &t
}

func setHTTPFail(r *Result, stage string, err error) {
	f := false
	r.HTTPOK = &f
	r.FailureCode = categorize(stage, err)
	r.FailureReason = formatReason(r.FailureCode, err)
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
