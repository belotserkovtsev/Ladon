package prober

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestCategorizeDNS(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want FailureCode
	}{
		{"nxdomain", &net.DNSError{Err: "no such host", IsNotFound: true}, CodeDNSNXDomain},
		{"timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, CodeDNSTimeout},
		{"servfail", &net.DNSError{Err: "server misbehaving"}, CodeDNSError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := categorize(stageDNS, tt.err); got != tt.want {
				t.Errorf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestCategorizeTCP(t *testing.T) {
	if got := categorize(stageTCP, syscall.ECONNREFUSED); got != CodeTCPRefused {
		t.Errorf("ECONNREFUSED → %q want %q", got, CodeTCPRefused)
	}
	if got := categorize(stageTCP, syscall.ECONNRESET); got != CodeTCPReset {
		t.Errorf("ECONNRESET → %q want %q", got, CodeTCPReset)
	}
	if got := categorize(stageTCP, syscall.EHOSTUNREACH); got != CodeTCPUnreachable {
		t.Errorf("EHOSTUNREACH → %q want %q", got, CodeTCPUnreachable)
	}

	// timeout via deadlineExceeded — wrapped in net.OpError as Go does at runtime.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	d := net.Dialer{}
	_, err := d.DialContext(ctx, "tcp", "10.255.255.1:80")
	if err == nil {
		t.Skip("expected dial to fail; environment lets it through")
	}
	if got := categorize(stageTCP, err); got != CodeTCPTimeout {
		t.Errorf("timeout dial → %q want %q (err=%v)", got, CodeTCPTimeout, err)
	}
}

func TestCategorizeTLSWrappedReset(t *testing.T) {
	// real-world shape: net.OpError wrapping a syscall.Errno
	wrapped := &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}
	if got := categorize(stageTLS, wrapped); got != CodeTLSReset {
		t.Errorf("wrapped ECONNRESET in TLS stage → %q want %q", got, CodeTLSReset)
	}
}

func TestCategorizeUnknownFallsThroughByStage(t *testing.T) {
	mystery := errors.New("something completely unrecognised")
	cases := map[string]FailureCode{
		stageDNS:  CodeDNSError,
		stageTCP:  CodeTCPError,
		stageTLS:  CodeTLSError,
		stageHTTP: CodeHTTPError,
	}
	for stage, want := range cases {
		if got := categorize(stage, mystery); got != want {
			t.Errorf("stage=%s → %q want %q", stage, got, want)
		}
	}
}

func TestFormatReason(t *testing.T) {
	if got := formatReason(CodeOK, nil); got != "" {
		t.Errorf("ok → %q want empty", got)
	}
	if got := formatReason(CodeNoIPs, nil); got != "no_ips" {
		t.Errorf("code-only → %q", got)
	}
	if got := formatReason(CodeTCPTimeout, errors.New("i/o timeout")); got != "tcp_timeout: i/o timeout" {
		t.Errorf("formatted → %q", got)
	}
}

func TestCategorizeTLSAlert(t *testing.T) {
	// alert 116 = certificate_required (TLS 1.3 RFC 8446 §6) — Apple Push,
	// FindMy, iCloud Private Relay. Must surface as a server-reachable signal,
	// not a generic tls_alert, so deploy logs/SQL can distinguish mTLS-driven
	// rejections from arbitrary alerts.
	if got := categorize(stageTLS, tls.AlertError(116)); got != CodeMTLSRequired {
		t.Errorf("alert 116 → %q want %q", got, CodeMTLSRequired)
	}
	// alert 47 = illegal_parameter (mask.icloud.com / mask.apple-dns.net
	// reject our ClientHello). Server-reachable but not an mTLS challenge.
	if got := categorize(stageTLS, tls.AlertError(47)); got != CodeTLSAlert {
		t.Errorf("alert 47 → %q want %q", got, CodeTLSAlert)
	}
	// Wrapped through io.EOF chain — common in HTTP-stage post-handshake
	// alerts. categorize must see the alert through the wrap, not bail at
	// the EOF check.
	wrapped := errors.Join(tls.AlertError(116), errors.New("read failure"))
	if got := categorize(stageHTTP, wrapped); got != CodeMTLSRequired {
		t.Errorf("wrapped alert 116 in HTTP stage → %q want %q", got, CodeMTLSRequired)
	}
}

func TestIsServerReachable(t *testing.T) {
	want := map[FailureCode]bool{
		CodeOK:                  false,
		CodeMTLSRequired:        true,
		CodeTLSAlert:            true,
		CodeHTTPCutoff:          false,
		CodeHTTPReset:           false,
		CodeTCPTimeout:          false,
		CodeTLSHandshakeTimeout: false,
	}
	for code, expect := range want {
		if got := IsServerReachable(code); got != expect {
			t.Errorf("IsServerReachable(%q) = %v want %v", code, got, expect)
		}
	}
}

func TestParseCode(t *testing.T) {
	tests := map[string]FailureCode{
		"":                                  CodeOK,
		"no_ips":                            CodeNoIPs,
		"tcp_timeout: i/o timeout":          CodeTCPTimeout,
		"tls13_block: handshake fail":       CodeTLS13Block,
		"mtls_required: tls: cert required": CodeMTLSRequired,
		"tls_alert: alert 47":               CodeTLSAlert,
		"remote:dial tcp 127.0.0.1":         CodeUnknown, // legacy "remote:..." prefix not in enum
		"definitely_not_a_code":             CodeUnknown,
	}
	for in, want := range tests {
		if got := parseCode(in); got != want {
			t.Errorf("parseCode(%q) = %q want %q", in, got, want)
		}
	}
}
