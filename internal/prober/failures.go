package prober

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
)

// FailureCode is a stable, grep-friendly classifier for probe failures.
// Stored as the prefix of FailureReason ("<code>: <raw err>"); kept as its
// own field so engine code can branch on category without parsing strings.
type FailureCode string

const (
	CodeOK FailureCode = ""

	CodeDNSNXDomain FailureCode = "dns_nxdomain"
	CodeDNSTimeout  FailureCode = "dns_timeout"
	CodeDNSError    FailureCode = "dns_error"
	CodeNoIPs       FailureCode = "no_ips"

	CodeTCPRefused     FailureCode = "tcp_refused"
	CodeTCPReset       FailureCode = "tcp_reset"
	CodeTCPTimeout     FailureCode = "tcp_timeout"
	CodeTCPUnreachable FailureCode = "tcp_unreachable"
	CodeTCPError       FailureCode = "tcp_error"

	CodeTLSHandshakeTimeout FailureCode = "tls_handshake_timeout"
	CodeTLSEOF              FailureCode = "tls_eof"
	CodeTLSReset            FailureCode = "tls_reset"
	CodeTLSAlert            FailureCode = "tls_alert"
	CodeTLSError            FailureCode = "tls_error"

	// CodeMTLSRequired is TLS alert 116 (certificate_required, RFC 8446 §6).
	// Server explicitly told us it needs a client certificate — proves the
	// server is reachable and that the failure is a server-side policy
	// decision, not a DPI block. Apple Push, FindMy, iCloud Private Relay
	// all use this. Treated as reachable in decision.Classify.
	CodeMTLSRequired FailureCode = "mtls_required"

	// CodeTLS13Block is set when TLS 1.3 fails but a 1.2-restricted retry
	// succeeds — strong hint that ClientHello inspection is targeting 1.3
	// (ECH/ESNI). Real-world signal for some RU-DPI deployments.
	CodeTLS13Block FailureCode = "tls13_block"

	CodeHTTPCutoff  FailureCode = "http_cutoff"
	CodeHTTPTimeout FailureCode = "http_timeout"
	CodeHTTPReset   FailureCode = "http_reset"
	CodeHTTPError   FailureCode = "http_error"

	// CodeRemote means the remote prober itself was unreachable — not a
	// verdict about the target. Engine treats as Hot (safe default) but
	// readers can distinguish from real DPI signals.
	CodeRemote FailureCode = "remote_unreachable"

	CodeUnknown FailureCode = "unknown"
)

// stage names categorize() understands.
const (
	stageDNS  = "dns"
	stageTCP  = "tcp"
	stageTLS  = "tls"
	stageHTTP = "http"
)

// categorize maps a Go error from a probe stage onto a FailureCode.
// Order matters: more specific checks first, generic last. Unknown errors
// fall through to <stage>_error rather than CodeUnknown so logs always say
// which stage owned them.
func categorize(stage string, err error) FailureCode {
	if err == nil {
		return CodeOK
	}

	if dnsErr := (*net.DNSError)(nil); errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return CodeDNSNXDomain
		}
		if dnsErr.IsTimeout {
			return CodeDNSTimeout
		}
		return CodeDNSError
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return CodeTCPRefused
	}
	if errors.Is(err, syscall.ECONNRESET) {
		switch stage {
		case stageTLS:
			return CodeTLSReset
		case stageHTTP:
			return CodeHTTPReset
		default:
			return CodeTCPReset
		}
	}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		return CodeTCPUnreachable
	}

	// TLS alert from the server — a typed signal that the server is alive
	// and explicitly rejected our connection. Distinct from a silent EOF
	// or a TCP-level cut. Whitelisted in decision: server is reachable,
	// not DPI. Must be checked BEFORE io.EOF because some alerts arrive
	// wrapped through the EOF chain on read errors.
	//
	// Detection is via string-match because Go's stdlib uses an internal
	// unexported `tls.alert` type for received peer alerts (the exported
	// tls.AlertError is only wrapped for QUIC transports). errors.As on
	// tls.AlertError is therefore unreliable for non-QUIC; we still try
	// the typed path first for correctness on QUIC + future Go versions
	// that may unify the types.
	var alert tls.AlertError
	if errors.As(err, &alert) {
		if uint8(alert) == 116 {
			return CodeMTLSRequired
		}
		return CodeTLSAlert
	}
	if rh := (tls.RecordHeaderError{}); errors.As(err, &rh) {
		return CodeTLSAlert
	}
	// String fallback for Go's internal tls.alert wrapping. Covers the
	// "remote error: tls: <description>" format Conn.in errors take. The
	// description set is small and stable (alertText in crypto/tls/alert.go).
	if errStr := err.Error(); strings.Contains(errStr, "remote error: tls:") {
		// alert 116 has the description "certificate required" — special-case
		// for mTLS observability before falling back to generic tls_alert.
		if strings.Contains(errStr, "certificate required") {
			return CodeMTLSRequired
		}
		return CodeTLSAlert
	}

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		switch stage {
		case stageTLS:
			return CodeTLSEOF
		case stageHTTP:
			return CodeHTTPCutoff
		}
	}

	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		switch stage {
		case stageDNS:
			return CodeDNSTimeout
		case stageTCP:
			return CodeTCPTimeout
		case stageTLS:
			return CodeTLSHandshakeTimeout
		case stageHTTP:
			return CodeHTTPTimeout
		}
	}
	// errors.As covers wrapped chains (e.g. *url.Error → *net.OpError → timeout).
	var nerrAs net.Error
	if errors.As(err, &nerrAs) && nerrAs.Timeout() {
		switch stage {
		case stageDNS:
			return CodeDNSTimeout
		case stageTCP:
			return CodeTCPTimeout
		case stageTLS:
			return CodeTLSHandshakeTimeout
		case stageHTTP:
			return CodeHTTPTimeout
		}
	}

	// Last resort: bucket by stage so logs stay actionable.
	switch stage {
	case stageDNS:
		return CodeDNSError
	case stageTCP:
		return CodeTCPError
	case stageTLS:
		return CodeTLSError
	case stageHTTP:
		return CodeHTTPError
	}
	return CodeUnknown
}

// formatReason renders a code+raw-err pair into the FailureReason string
// engine and SQLite store. Empty err keeps the legacy single-token format
// ("no_ips", "remote_unreachable") so existing log greps don't break.
func formatReason(code FailureCode, err error) string {
	if code == CodeOK {
		return ""
	}
	if err == nil {
		return string(code)
	}
	return string(code) + ": " + err.Error()
}

// parseCode pulls a FailureCode back out of a FailureReason string. Used by
// RemoteProber when the remote is older and only gave us the legacy reason
// without an explicit code field. Tolerant: unknown prefixes return
// CodeUnknown rather than erroring.
func parseCode(reason string) FailureCode {
	if reason == "" {
		return CodeOK
	}
	prefix := reason
	if i := strings.IndexByte(reason, ':'); i > 0 {
		prefix = reason[:i]
	}
	switch FailureCode(prefix) {
	case CodeDNSNXDomain, CodeDNSTimeout, CodeDNSError, CodeNoIPs,
		CodeTCPRefused, CodeTCPReset, CodeTCPTimeout, CodeTCPUnreachable, CodeTCPError,
		CodeTLSHandshakeTimeout, CodeTLSEOF, CodeTLSReset, CodeTLSAlert, CodeTLSError, CodeTLS13Block,
		CodeMTLSRequired,
		CodeHTTPCutoff, CodeHTTPTimeout, CodeHTTPReset, CodeHTTPError,
		CodeRemote, CodeUnknown:
		return FailureCode(prefix)
	}
	return CodeUnknown
}

// IsServerReachable reports whether a FailureCode represents a typed
// signal that the server is alive and reachable — even though the probe
// "failed" in the strict TCP+TLS+HTTP-success sense. These codes come from
// the server actively responding (TLS alerts, mTLS challenges) rather than
// DPI silently dropping or resetting. The engine treats them as Ignore.
func IsServerReachable(c FailureCode) bool {
	switch c {
	case CodeTLSAlert, CodeMTLSRequired:
		return true
	}
	return false
}
