package decision

import (
	"strings"
	"testing"

	"github.com/belotserkovtsev/ladon/internal/prober"
)

func TestClassifyRemote(t *testing.T) {
	cases := []struct {
		name string
		in   prober.Result
		want RemoteState
	}{
		{
			name: "transport failure (CodeRemote)",
			in:   prober.Result{FailureCode: prober.CodeRemote},
			want: RemoteUnavailable,
		},
		{
			name: "transport failure (legacy reason prefix)",
			in:   prober.Result{FailureReason: "remote:dial: i/o timeout"},
			want: RemoteUnavailable,
		},
		{
			name: "tcp failed",
			in:   prober.Result{TCPOK: false, TLSOK: false},
			want: RemoteFail,
		},
		{
			name: "tls failed",
			in:   prober.Result{TCPOK: true, TLSOK: false},
			want: RemoteFail,
		},
		{
			name: "tcp+tls ok, http nil (legacy remote, no http stage)",
			in:   prober.Result{TCPOK: true, TLSOK: true},
			want: RemoteTCPTLSOnly,
		},
		{
			name: "tcp+tls ok, http failed (server-side severing)",
			in:   prober.Result{TCPOK: true, TLSOK: true, HTTPOK: ptrBool(false)},
			want: RemoteHTTPFail,
		},
		{
			name: "full chain ok",
			in:   prober.Result{TCPOK: true, TLSOK: true, HTTPOK: ptrBool(true)},
			want: RemoteOK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyRemote(tc.in); got != tc.want {
				t.Fatalf("ClassifyRemote(%+v) = %v; want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCombineExitCompare(t *testing.T) {
	cases := []struct {
		name        string
		localCode   prober.FailureCode
		remote      RemoteState
		wantVerdict Verdict
		wantTagSubs string // substring expected in tag (for grep-friendliness)
	}{
		// Remote unavailable — keep local Hot regardless of code.
		{"tcp_timeout / unavail → hot", prober.CodeTCPTimeout, RemoteUnavailable, Hot, "unavailable"},
		{"http_cutoff / unavail → hot", prober.CodeHTTPCutoff, RemoteUnavailable, Hot, "unavailable"},

		// Remote OK — full chain success confirms DPI on local.
		{"tcp_timeout / remote ok → hot", prober.CodeTCPTimeout, RemoteOK, Hot, "ok"},
		{"tls_handshake_timeout / remote ok → hot", prober.CodeTLSHandshakeTimeout, RemoteOK, Hot, "ok"},
		{"http_reset / remote ok → hot", prober.CodeHTTPReset, RemoteOK, Hot, "ok"},
		{"http_cutoff / remote ok → hot", prober.CodeHTTPCutoff, RemoteOK, Hot, "ok"},

		// Remote HTTP-fail — server-side severing, never DPI.
		// The Yandex-class fix: BOTH vantages http_cutoff → Ignore (was Hot).
		{"http_cutoff / remote http_fail → ignore (yandex fix)", prober.CodeHTTPCutoff, RemoteHTTPFail, Ignore, "http_fail"},
		{"http_timeout / remote http_fail → ignore", prober.CodeHTTPTimeout, RemoteHTTPFail, Ignore, "http_fail"},
		{"http_error / remote http_fail → ignore", prober.CodeHTTPError, RemoteHTTPFail, Ignore, "http_fail"},
		// Even high-conf codes get Ignore here — if remote sees TCP+TLS ok
		// but HTTP fails, the target is fundamentally not-routing-fixable.
		{"tls_handshake_timeout / remote http_fail → ignore", prober.CodeTLSHandshakeTimeout, RemoteHTTPFail, Ignore, "http_fail"},

		// Remote TCP/TLS fail — both vantages can't even handshake. Not DPI.
		{"tcp_timeout / remote fail → ignore", prober.CodeTCPTimeout, RemoteFail, Ignore, "fail"},
		{"http_cutoff / remote fail → ignore", prober.CodeHTTPCutoff, RemoteFail, Ignore, "fail"},

		// Legacy remote (TCP+TLS ok, HTTP not run).
		// High-conf codes: TCP/TLS evidence is enough → Hot.
		{"tcp_timeout / remote tcp+tls-only → hot", prober.CodeTCPTimeout, RemoteTCPTLSOnly, Hot, "tcp+tls-ok"},
		{"tls_handshake_timeout / remote tcp+tls-only → hot", prober.CodeTLSHandshakeTimeout, RemoteTCPTLSOnly, Hot, "tcp+tls-ok"},
		{"http_reset / remote tcp+tls-only → hot", prober.CodeHTTPReset, RemoteTCPTLSOnly, Hot, "tcp+tls-ok"},
		// Ambiguous codes: TCP/TLS evidence not enough — could still be
		// server-side severing on HTTP. Conservative Ignore.
		{"http_cutoff / remote tcp+tls-only → ignore (ambig)", prober.CodeHTTPCutoff, RemoteTCPTLSOnly, Ignore, "ambig"},
		{"http_timeout / remote tcp+tls-only → ignore (ambig)", prober.CodeHTTPTimeout, RemoteTCPTLSOnly, Ignore, "ambig"},
		{"http_error / remote tcp+tls-only → ignore (ambig)", prober.CodeHTTPError, RemoteTCPTLSOnly, Ignore, "ambig"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotVerdict, gotTag := CombineExitCompare(tc.localCode, tc.remote)
			if gotVerdict != tc.wantVerdict {
				t.Errorf("CombineExitCompare(%q, %v) verdict = %s; want %s",
					tc.localCode, tc.remote, gotVerdict, tc.wantVerdict)
			}
			if !strings.Contains(gotTag, tc.wantTagSubs) {
				t.Errorf("CombineExitCompare(%q, %v) tag = %q; want substring %q",
					tc.localCode, tc.remote, gotTag, tc.wantTagSubs)
			}
		})
	}
}

func TestIsAmbiguousCode(t *testing.T) {
	ambig := []prober.FailureCode{
		prober.CodeHTTPCutoff, prober.CodeHTTPTimeout, prober.CodeHTTPError,
	}
	for _, c := range ambig {
		if !isAmbiguousCode(c) {
			t.Errorf("isAmbiguousCode(%q) = false; want true", c)
		}
	}
	notAmbig := []prober.FailureCode{
		prober.CodeOK, prober.CodeTCPTimeout, prober.CodeTLSHandshakeTimeout,
		prober.CodeHTTPReset, prober.CodeMTLSRequired, prober.CodeDNSNXDomain,
	}
	for _, c := range notAmbig {
		if isAmbiguousCode(c) {
			t.Errorf("isAmbiguousCode(%q) = true; want false", c)
		}
	}
}

func TestIsHighConfDPICode(t *testing.T) {
	highConf := []prober.FailureCode{
		prober.CodeTCPRefused, prober.CodeTCPReset, prober.CodeTCPTimeout,
		prober.CodeTCPUnreachable, prober.CodeTCPError,
		prober.CodeTLSHandshakeTimeout, prober.CodeTLSEOF, prober.CodeTLSReset,
		prober.CodeTLSError, prober.CodeTLS13Block,
		prober.CodeHTTPReset,
	}
	for _, c := range highConf {
		if !isHighConfDPICode(c) {
			t.Errorf("isHighConfDPICode(%q) = false; want true", c)
		}
	}
	notHighConf := []prober.FailureCode{
		prober.CodeOK, prober.CodeHTTPCutoff, prober.CodeHTTPTimeout,
		prober.CodeHTTPError, prober.CodeMTLSRequired, prober.CodeTLSAlert,
		prober.CodeDNSNXDomain,
	}
	for _, c := range notHighConf {
		if isHighConfDPICode(c) {
			t.Errorf("isHighConfDPICode(%q) = true; want false", c)
		}
	}
}
