package decision

import (
	"testing"

	"github.com/belotserkovtsev/ladon/internal/prober"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		in   prober.Result
		want Verdict
	}{
		{
			name: "dns fail → ignore (not our problem)",
			in:   prober.Result{DNSOK: false},
			want: Clear,
		},
		{
			name: "tcp fail → hot (reachable name, blocked host)",
			in:   prober.Result{DNSOK: true, TCPOK: false},
			want: Blocked,
		},
		{
			name: "tls fail → hot (handshake interception)",
			in:   prober.Result{DNSOK: true, TCPOK: true, TLSOK: false},
			want: Blocked,
		},
		{
			name: "everything ok → ignore (direct path works)",
			in:   prober.Result{DNSOK: true, TCPOK: true, TLSOK: true},
			want: Clear,
		},
		{
			name: "tls ok, http cutoff → hot (L7 DPI severs stream)",
			in:   prober.Result{DNSOK: true, TCPOK: true, TLSOK: true, HTTPOK: ptrBool(false)},
			want: Blocked,
		},
		{
			name: "tls ok, http ok → ignore (real end-to-end response)",
			in:   prober.Result{DNSOK: true, TCPOK: true, TLSOK: true, HTTPOK: ptrBool(true)},
			want: Clear,
		},
		{
			name: "tls ok, http nil (older remote) → ignore (back-compat)",
			in:   prober.Result{DNSOK: true, TCPOK: true, TLSOK: true},
			want: Clear,
		},
		{
			name: "tls13_block (1.2 fallback ok, 1.3 path-blocked) → hot",
			in: prober.Result{
				DNSOK: true, TCPOK: true, TLSOK: true,
				HTTPOK:      ptrBool(true),
				FailureCode: prober.CodeTLS13Block,
			},
			want: Blocked,
		},
		{
			// Handshake reachable (TLSOK true) but the cert was substituted, so
			// FailureCode wins over the otherwise-Clear TCP+TLS+no-HTTP shape.
			name: "tls_intercept (cert-substitution MITM) → hot",
			in: prober.Result{
				DNSOK: true, TCPOK: true, TLSOK: true,
				FailureCode: prober.CodeTLSIntercept,
			},
			want: Blocked,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.in); got != tc.want {
				t.Fatalf("Classify(%+v) = %s; want %s", tc.in, got, tc.want)
			}
		})
	}
}

func ptrBool(b bool) *bool { return &b }
