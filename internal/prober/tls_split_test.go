package prober

import (
	"crypto/tls"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)


// TestTLSSplit_Default exercises the unrestricted 1.3 path against a real
// httptest TLS server. Both sides default to 1.3, so TLS13OK should be set
// and the 1.2 retry should not fire.
func TestTLSSplit_Default(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	host, port := splitHostPort(t, srv.Listener.Addr().String())
	r := Result{Domain: "example.com", ResolvedIPs: []string{host}}
	if conn := probeTLSStaged(&r, host, port, 2*time.Second); conn != nil {
		conn.Close()
	}

	if !r.TLSOK {
		t.Fatalf("TLSOK=false reason=%q code=%q", r.FailureReason, r.FailureCode)
	}
	if r.TLS13OK == nil || !*r.TLS13OK {
		t.Errorf("TLS13OK=%v want ptr(true)", r.TLS13OK)
	}
	if r.TLS12OK != nil {
		t.Errorf("TLS12OK=%v want nil (1.2 retry should not fire after 1.3 succeeds)", r.TLS12OK)
	}
}

// TestTLSSplit_Server12Only — server caps at TLS 1.2. The unrestricted dial
// negotiates down to 1.2 cleanly, so TLS12OK=ptr(true), TLS13OK=nil.
func TestTLSSplit_Server12Only(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	host, port := splitHostPort(t, srv.Listener.Addr().String())
	r := Result{Domain: "example.com", ResolvedIPs: []string{host}}
	if conn := probeTLSStaged(&r, host, port, 2*time.Second); conn != nil {
		conn.Close()
	}

	if !r.TLSOK {
		t.Fatalf("TLSOK=false reason=%q code=%q", r.FailureReason, r.FailureCode)
	}
	if r.TLS12OK == nil || !*r.TLS12OK {
		t.Errorf("TLS12OK=%v want ptr(true)", r.TLS12OK)
	}
	if r.TLS13OK != nil {
		t.Errorf("TLS13OK=%v want nil — 1.3 dial succeeded by negotiating 1.2", r.TLS13OK)
	}
}

// TestTLSSplit_BothFail — listener accepts then closes. Both 1.3 and 1.2
// attempts must fail; FailureCode/Reason carry the last error.
func TestTLSSplit_BothFail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	host, port := splitHostPort(t, ln.Addr().String())
	r := Result{Domain: "example.com", ResolvedIPs: []string{host}}
	if conn := probeTLSStaged(&r, host, port, 1*time.Second); conn != nil {
		conn.Close()
		t.Fatal("probeTLSStaged returned a live conn on a closed-on-accept listener")
	}

	if r.TLSOK {
		t.Fatal("TLSOK=true on closed-on-accept listener — should fail")
	}
	if r.TLS13OK == nil || *r.TLS13OK {
		t.Errorf("TLS13OK=%v want ptr(false)", r.TLS13OK)
	}
	if r.TLS12OK == nil || *r.TLS12OK {
		t.Errorf("TLS12OK=%v want ptr(false)", r.TLS12OK)
	}
	if r.FailureCode == CodeOK {
		t.Errorf("FailureCode unset; want a tls_* code")
	}
	if !strings.HasPrefix(string(r.FailureCode), "tls_") {
		t.Errorf("FailureCode=%q want tls_*", r.FailureCode)
	}
}

// TestLiftTLS13Verdict tests the post-probe lift that promotes a
// "1.3 path-active failed, 1.2 ok, HTTP ok" result to CodeTLS13Block.
// Integration-testing a forged-alert DPI scenario requires a low-level
// TLS server that injects RST mid-handshake based on advertised
// supported_versions — out of scope here. The unit test covers the
// verdict logic; full chain is exercised in production deploy logs.
func TestLiftTLS13Verdict(t *testing.T) {
	tr, fa := true, false
	cases := []struct {
		name string
		in   Result
		want FailureCode
	}{
		{
			name: "1.3 fail + 1.2 ok + HTTP ok → tls13_block",
			in:   Result{TLS13OK: &fa, TLS12OK: &tr, HTTPOK: &tr, FailureCode: CodeOK},
			want: CodeTLS13Block,
		},
		{
			name: "1.3 fail + 1.2 ok + HTTP nil (legacy probe-server) → tls13_block",
			in:   Result{TLS13OK: &fa, TLS12OK: &tr, FailureCode: CodeOK},
			want: CodeTLS13Block,
		},
		{
			name: "server is 1.2-only (TLS13OK=nil) → no lift",
			in:   Result{TLS13OK: nil, TLS12OK: &tr, HTTPOK: &tr, FailureCode: CodeOK},
			want: CodeOK,
		},
		{
			name: "1.3 ok → no lift",
			in:   Result{TLS13OK: &tr, HTTPOK: &tr, FailureCode: CodeOK},
			want: CodeOK,
		},
		{
			name: "1.3 fail + 1.2 fail → no lift (existing failure stands)",
			in:   Result{TLS13OK: &fa, TLS12OK: &fa, FailureCode: CodeTLSReset},
			want: CodeTLSReset,
		},
		{
			name: "1.3 fail + 1.2 ok + HTTP fail → no lift (HTTP failure is more proximate)",
			in:   Result{TLS13OK: &fa, TLS12OK: &tr, HTTPOK: &fa, FailureCode: CodeHTTPCutoff},
			want: CodeHTTPCutoff,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.in
			liftTLS13Verdict(&r)
			if r.FailureCode != tc.want {
				t.Errorf("FailureCode=%q want %q", r.FailureCode, tc.want)
			}
		})
	}
}

func splitHostPort(t *testing.T, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
