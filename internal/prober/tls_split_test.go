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
	probeTLSStaged(&r, host, port, 2*time.Second)

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
	probeTLSStaged(&r, host, port, 2*time.Second)

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
	probeTLSStaged(&r, host, port, 1*time.Second)

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

func splitHostPort(t *testing.T, addr string) (string, string) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
