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

	utls "github.com/refraction-networking/utls"
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

// Probe runs DNS → TCP:443 → TLS-SNI → HTTP against domain. Uses the
// default fingerprint; ad-hoc CLI calls and tests get the same browser
// mimic as the engine. For non-default fingerprints (engine, probe-server)
// use the LocalProber wrapper, which threads its configured Fingerprint
// down through all stages.
func Probe(ctx context.Context, domain string, timeout time.Duration) Result {
	return probeWithFingerprint(ctx, domain, nil, DefaultFingerprint, timeout)
}

// ProbeWithFingerprint is Probe but with a caller-chosen browser
// fingerprint for the TLS stage. Empty fp falls back to DefaultFingerprint.
func ProbeWithFingerprint(ctx context.Context, domain string, fp Fingerprint, timeout time.Duration) Result {
	return probeWithFingerprint(ctx, domain, nil, fp, timeout)
}

func probeWithFingerprint(ctx context.Context, domain string, ips []string, fp Fingerprint, timeout time.Duration) Result {
	if fp == "" {
		fp = DefaultFingerprint
	}
	if len(ips) > 0 {
		return probeIPsWithFingerprint(ctx, domain, ips, fp, timeout)
	}
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
	return probeTCPTLS(ctx, r, started, timeout, fp)
}

// ProbeIPs runs TCP:443 → TLS-SNI → HTTP against a caller-supplied IP
// list with the default fingerprint. Used when the client's resolver
// already gave us the answers (via dns_cache) — avoids a redundant DNS
// lookup that might disagree with the client's view.
func ProbeIPs(ctx context.Context, domain string, ips []string, timeout time.Duration) Result {
	return probeIPsWithFingerprint(ctx, domain, ips, DefaultFingerprint, timeout)
}

// ProbeIPsWithFingerprint is ProbeIPs but with a caller-chosen browser
// fingerprint. Empty fp falls back to DefaultFingerprint.
func ProbeIPsWithFingerprint(ctx context.Context, domain string, ips []string, fp Fingerprint, timeout time.Duration) Result {
	return probeIPsWithFingerprint(ctx, domain, ips, fp, timeout)
}

func probeIPsWithFingerprint(ctx context.Context, domain string, ips []string, fp Fingerprint, timeout time.Duration) Result {
	if fp == "" {
		fp = DefaultFingerprint
	}
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
	return probeTCPTLS(ctx, r, started, timeout, fp)
}

// probeTCPTLS races TCP:443 connects across up to MaxIPsToTry IPs in parallel,
// takes the first success, then runs TLS-SNI + HTTP on that IP using the
// supplied browser fingerprint for the TLS stage. Losing dials are cancelled
// via the shared context.
func probeTCPTLS(ctx context.Context, r Result, started time.Time, timeout time.Duration, fp Fingerprint) Result {
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

	conn := probeTLSStaged(&r, reachable, "443", timeout, fp)
	if conn != nil {
		probeHTTPStaged(&r, conn, timeout)
		conn.Close()
	}
	r.LatencyMS = int(time.Since(started) / time.Millisecond)
	return r
}

// probeTLSStaged runs the TLS handshake first via uTLS with the supplied
// browser fingerprint (1.3 path), and on failure retries with Go's stdlib
// tls.Dial pinned to TLS 1.2 — covering legacy 1.2-only servers that the
// uTLS Chrome preset can't satisfy.
//
// The mimic-first design exists because RU-DPI (and similar) increasingly
// blacklists ClientHello fingerprints rather than TLS as a whole: probing
// with Go's stdlib fingerprint passes through DPI that a real Chrome user
// gets cut by, producing false-Ignore verdicts. uTLS reproduces the
// browser ClientHello byte-for-byte, so the engine sees what real clients
// see.
//
// Returns a live net.Conn on success (uTLS UConn implements net.Conn, so
// the HTTP stage works through the interface). Returns nil when both
// attempts fail OR when the failure is server-reachable (typed TLS alert):
// in the latter case TLSOK and HTTPOK are set to true so decision.Classify
// gives Ignore, but the code/reason persist for observability.
func probeTLSStaged(r *Result, ip, port string, timeout time.Duration, fp Fingerprint) net.Conn {
	conn, code, reason, version := tlsHandshakeMimic(ip, port, r.Domain, fp, timeout)
	if conn != nil {
		r.TLSOK = true
		recordTLSVersion(r, version)
		return conn
	}
	// Mimic attempt failed. Two sub-cases:
	//  1. Server actively rejected with a TLS alert → server is reachable,
	//     no point retrying with 1.2 (the rejection is policy, not version).
	//     Surface via TLSOK=true + HTTPOK=true so Classify gives Ignore,
	//     but keep the code/reason for observability.
	//  2. Real failure (timeout, RST, EOF, etc.) → fall through to the
	//     1.2 fallback for legacy 1.2-only servers.
	if IsServerReachable(code) {
		r.TLSOK = true
		t := true
		r.HTTPOK = &t
		r.FailureCode = code
		r.FailureReason = reason
		return nil
	}

	// Real failure path. Stash the error so it survives if the 1.2 fallback
	// also fails.
	r.FailureCode = code
	r.FailureReason = reason
	f := false
	r.TLS13OK = &f

	// 1.2 fallback uses Go's stdlib tls.Dial — for genuinely 1.2-only
	// servers the fingerprint mimic isn't the issue (1.2 servers don't
	// see Chrome 1.3 ClientHello structure anyway). New TCP connection;
	// the previous handshake usually drops the socket.
	conn2, code2, _, _ := tlsHandshakeFallback12(ip, port, r.Domain, timeout)
	if conn2 != nil {
		t := true
		r.TLS12OK = &t
		r.TLSOK = true
		// Clear the failure carried from the 1.3 attempt — TLS as a whole
		// succeeded. TLS13OK=false stays for observability.
		r.FailureCode = CodeOK
		r.FailureReason = ""
		return conn2
	}
	// 1.2 also failed — but if it failed with a server-reachable code,
	// trust that signal over the 1.3 result.
	if IsServerReachable(code2) {
		r.TLSOK = true
		t := true
		r.HTTPOK = &t
		r.FailureCode = code2
		r.FailureReason = formatReason(code2, nil)
		return nil
	}
	r.TLS12OK = &f
	return nil
}

// tlsHandshakeMimic runs the primary TLS handshake using uTLS with the
// supplied browser fingerprint. Returns a live *utls.UConn (which
// implements net.Conn) on success, or nil + code/reason on failure.
func tlsHandshakeMimic(ip, port, sni string, fp Fingerprint, timeout time.Duration) (conn net.Conn, code FailureCode, reason string, version uint16) {
	rawConn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), timeout)
	if err != nil {
		c := categorize(stageTCP, err)
		return nil, c, formatReason(c, err), 0
	}

	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // #nosec G402 — probing reachability, not identity
	}
	uconn := utls.UClient(rawConn, cfg, lookupHelloID(fp))
	if err := uconn.SetDeadline(time.Now().Add(timeout)); err != nil {
		uconn.Close()
		c := categorize(stageTLS, err)
		return nil, c, formatReason(c, err), 0
	}
	if err := uconn.Handshake(); err != nil {
		uconn.Close()
		c := categorize(stageTLS, err)
		return nil, c, formatReason(c, err), 0
	}
	// Clear the deadline so the HTTP stage can apply its own.
	_ = uconn.SetDeadline(time.Time{})
	state := uconn.ConnectionState()
	return uconn, CodeOK, "", state.Version
}

// tlsHandshakeFallback12 is the legacy 1.2-only path via Go's stdlib
// tls.Dial. Used only when the uTLS mimic attempt fails — covers servers
// that genuinely can't speak TLS 1.3.
func tlsHandshakeFallback12(ip, port, sni string, timeout time.Duration) (conn *tls.Conn, code FailureCode, reason string, version uint16) {
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // #nosec G402
		MaxVersion:         tls.VersionTLS12,
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
func probeHTTPStaged(r *Result, conn net.Conn, timeout time.Duration) {
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
	code := categorize(stage, err)
	r.FailureCode = code
	r.FailureReason = formatReason(code, err)
	// If the server is the source of the rejection (typed TLS alert during
	// HTTP read — typical for post-handshake mTLS challenges like Apple
	// Push / FindMy / iCloud Private Relay), treat as reachable. The
	// failure code stays for observability; HTTPOK flips to true so
	// decision.Classify gives Ignore.
	if IsServerReachable(code) {
		t := true
		r.HTTPOK = &t
		return
	}
	f := false
	r.HTTPOK = &f
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
