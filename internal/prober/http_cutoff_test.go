package prober

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestHTTPCutoff_FullResponse — real httptest server returns 200 OK with a
// short body. Probe should mark HTTPOK=true.
func TestHTTPCutoff_FullResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello world")
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.Listener.Addr().String())
	r := Result{Domain: "example.com", ResolvedIPs: []string{host}}
	conn := probeTLSStaged(&r, host, port, 2*time.Second)
	if conn == nil {
		t.Fatalf("TLS handshake failed: %s / %s", r.FailureCode, r.FailureReason)
	}
	probeHTTPStaged(&r, conn, 2*time.Second)
	conn.Close()

	if r.HTTPOK == nil || !*r.HTTPOK {
		t.Errorf("HTTPOK=%v want ptr(true) (code=%q reason=%q)", r.HTTPOK, r.FailureCode, r.FailureReason)
	}
}

// TestHTTPCutoff_404 — server returns 404. Probe should still treat the
// path as reachable; we're not classifying server semantics.
func TestHTTPCutoff_404(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.Listener.Addr().String())
	r := Result{Domain: "example.com", ResolvedIPs: []string{host}}
	conn := probeTLSStaged(&r, host, port, 2*time.Second)
	if conn == nil {
		t.Fatalf("TLS handshake failed")
	}
	probeHTTPStaged(&r, conn, 2*time.Second)
	conn.Close()

	if r.HTTPOK == nil || !*r.HTTPOK {
		t.Errorf("HTTPOK=%v want ptr(true) — 404 with body counts as reachable", r.HTTPOK)
	}
}

// TestHTTPCutoff_StreamSevered — TLS server that completes the handshake
// then immediately closes the underlying conn before sending any HTTP
// response bytes. Mimics a DPI cutting at the application layer.
func TestHTTPCutoff_StreamSevered(t *testing.T) {
	ln, err := tls.Listen("tcp", "127.0.0.1:0", testTLSConfig(t))
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
			// Force the handshake (so the client's TLS stage succeeds), then
			// drop the connection without writing a byte of HTTP. Anything
			// that severs *after* TLS but before HTTP completes lands here.
			if tlsConn, ok := c.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
			c.Close()
		}
	}()

	host, port := splitHostPort(t, ln.Addr().String())
	r := Result{Domain: "example.com", ResolvedIPs: []string{host}}
	conn := probeTLSStaged(&r, host, port, 2*time.Second)
	if conn == nil {
		t.Fatalf("TLS handshake failed: %s / %s", r.FailureCode, r.FailureReason)
	}
	probeHTTPStaged(&r, conn, 2*time.Second)
	conn.Close()

	if r.HTTPOK == nil || *r.HTTPOK {
		t.Errorf("HTTPOK=%v want ptr(false) — stream was severed pre-response", r.HTTPOK)
	}
	if !strings.HasPrefix(string(r.FailureCode), "http_") {
		t.Errorf("FailureCode=%q want http_*", r.FailureCode)
	}
}

// testTLSConfig builds a server-side tls.Config with a fresh self-signed
// cert. Generated per test rather than reusing a fixture so the suite has
// no on-disk crypto state to manage.
func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// keep otherwise-unused imports happy when this file is the only consumer
var (
	_ = net.Listen
	_ = httptest.NewTLSServer
)
