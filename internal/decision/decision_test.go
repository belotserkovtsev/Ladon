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
			want: Ignore,
		},
		{
			name: "tcp fail → hot (reachable name, blocked host)",
			in:   prober.Result{DNSOK: true, TCPOK: false},
			want: Hot,
		},
		{
			name: "tls fail → hot (handshake interception)",
			in:   prober.Result{DNSOK: true, TCPOK: true, TLSOK: false},
			want: Hot,
		},
		{
			name: "everything ok → ignore (direct path works)",
			in:   prober.Result{DNSOK: true, TCPOK: true, TLSOK: true},
			want: Ignore,
		},
		{
			name: "tls ok, http cutoff → hot (L7 DPI severs stream)",
			in:   prober.Result{DNSOK: true, TCPOK: true, TLSOK: true, HTTPOK: ptrBool(false)},
			want: Hot,
		},
		{
			name: "tls ok, http ok → ignore (real end-to-end response)",
			in:   prober.Result{DNSOK: true, TCPOK: true, TLSOK: true, HTTPOK: ptrBool(true)},
			want: Ignore,
		},
		{
			name: "tls ok, http nil (older remote) → ignore (back-compat)",
			in:   prober.Result{DNSOK: true, TCPOK: true, TLSOK: true},
			want: Ignore,
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
