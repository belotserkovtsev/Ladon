// Standalone ladon-style QUIC probe that tries multiple ALPN / SNI /
// config variations against a target. Run:
//
//   go run -tags probe quic-probe-variants.go api.anthropic.com
//   go run -tags probe quic-probe-variants.go riot-client.dyn.riotcdn.net
//
// Goal: for each variant, see if the QUIC handshake completes OR what
// error the server returns. Tells us whether our production h3-only
// probe is methodologically wrong (server supports QUIC under a
// different ALPN) or the servers just don't do QUIC at all.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
)

type variant struct {
	name       string
	alpn       []string
	skipSNI    bool
	skipVerify bool
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: go run -tags probe quic-probe-variants.go <domain>")
		os.Exit(1)
	}
	domain := os.Args[1]

	ips, err := net.DefaultResolver.LookupHost(context.Background(), domain)
	if err != nil {
		fmt.Printf("resolve %s: %v\n", domain, err)
		os.Exit(1)
	}
	ip := ips[0]
	addr := net.JoinHostPort(ip, "443")
	fmt.Printf("== %s → %s ==\n\n", domain, ip)

	variants := []variant{
		{"h3 only (current prod)", []string{"h3"}, false, true},
		{"h3 draft-29", []string{"h3-29"}, false, true},
		{"h3 draft-32", []string{"h3-32"}, false, true},
		{"h3 + drafts", []string{"h3", "h3-29", "h3-32", "h3-34"}, false, true},
		{"no ALPN", []string{}, false, true},
		{"hq-interop (IETF interop)", []string{"hq-interop"}, false, true},
		{"verify cert (no InsecureSkip)", []string{"h3"}, false, false},
		{"no SNI + h3", []string{"h3"}, true, true},
	}

	for _, v := range variants {
		tc := &tls.Config{
			NextProtos:         v.alpn,
			InsecureSkipVerify: v.skipVerify,
		}
		if !v.skipSNI {
			tc.ServerName = domain
		}
		probe(addr, v, tc)
	}
}

func probe(addr string, v variant, tc *tls.Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	t0 := time.Now()
	conn, err := quic.DialAddr(ctx, addr, tc, &quic.Config{
		HandshakeIdleTimeout: 3 * time.Second,
	})
	dur := time.Since(t0).Milliseconds()
	if err != nil {
		fmt.Printf("  %-32s  FAIL  (%4dms)  %v\n", v.name, dur, err)
		return
	}
	alpn := conn.ConnectionState().TLS.NegotiatedProtocol
	fmt.Printf("  %-32s  OK    (%4dms)  negotiated_alpn=%q\n", v.name, dur, alpn)
	_ = conn.CloseWithError(0, "probe done")
}
