package prober

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestInterceptDetectsSelfSigned — a self-signed httptest server is the exact
// shape of a provider cert-substitution stub: the handshake completes but the
// cert chains to no trusted root. interceptCode must flag it.
func TestInterceptDetectsSelfSigned(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	host, port := splitHostPort(t, srv.Listener.Addr().String())
	r := Result{Domain: "example.com", ResolvedIPs: []string{host}}
	conn := probeTLSStaged(&r, host, port, 2*time.Second)
	if conn == nil {
		t.Fatalf("handshake failed: %s / %s", r.FailureCode, r.FailureReason)
	}
	defer conn.Close()

	if got := interceptCode(r.Domain, conn.ConnectionState()); got != CodeTLSIntercept {
		t.Fatalf("interceptCode=%q want %q (self-signed cert)", got, CodeTLSIntercept)
	}
}

// TestInterceptIgnoresNameMismatch — a properly CA-issued cert that simply
// doesn't cover the name we asked for must NOT be flagged. Real hosts do this
// all the time (legacy service endpoints, shared CDN certs, virtual hosts);
// treating it as interception tunnels traffic that was never blocked.
func TestInterceptIgnoresNameMismatch(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "real.example"},
		DNSNames:     []string{"real.example"}, // deliberately NOT the name we ask for
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}

	// Asking for a name the cert doesn't cover, but the chain is trusted.
	if got := interceptCodeWithRoots("legacy-endpoint.example", state, roots); got != CodeOK {
		t.Fatalf("interceptCode=%q want CodeOK — trusted CA cert with a name mismatch is not interception", got)
	}
	// Same cert, untrusted chain → that IS the interception signature.
	if got := interceptCodeWithRoots("real.example", state, x509.NewCertPool()); got != CodeTLSIntercept {
		t.Fatalf("interceptCode=%q want %q for an untrusted chain", got, CodeTLSIntercept)
	}
}

// TestInterceptSkipsNonName — an empty or IP-literal SNI has no name that could
// have been substituted, so interceptCode must stay silent.
func TestInterceptSkipsNonName(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	host, port := splitHostPort(t, srv.Listener.Addr().String())

	for _, sni := range []string{"", host} { // host is an IP literal (127.0.0.1)
		r := Result{Domain: sni, ResolvedIPs: []string{host}}
		conn := probeTLSStaged(&r, host, port, 2*time.Second)
		if conn == nil {
			t.Fatalf("handshake failed for sni=%q", sni)
		}
		if got := interceptCode(sni, conn.ConnectionState()); got != CodeOK {
			t.Errorf("interceptCode(%q)=%q want CodeOK (no name to verify)", sni, got)
		}
		conn.Close()
	}
}
