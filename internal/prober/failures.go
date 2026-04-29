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

	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		switch stage {
		case stageTLS:
			return CodeTLSEOF
		case stageHTTP:
			return CodeHTTPCutoff
		}
	}

	// TLS alert / record header — handshake actually started but server (or
	// middlebox) rejected it. Distinct from a silent EOF.
	if rh := (tls.RecordHeaderError{}); errors.As(err, &rh) {
		return CodeTLSAlert
	}
	if alert := (*tls.AlertError)(nil); errors.As(err, &alert) {
		return CodeTLSAlert
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
		CodeHTTPCutoff, CodeHTTPTimeout, CodeHTTPReset, CodeHTTPError,
		CodeRemote, CodeUnknown:
		return FailureCode(prefix)
	}
	return CodeUnknown
}
