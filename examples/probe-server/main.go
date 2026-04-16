// Package main is a reference implementation of the probe-server contract that
// ladon's RemoteProber speaks. It runs a local TCP+TLS probe against the
// target and returns the result — the same thing ladon's LocalProber does.
//
// The point isn't the TCP/TLS logic — ladon has that built in. The point is
// to show what the HTTP wire-format looks like, so operators can drop in
// their own probe logic (a 4G SIM, a home Pi, a browser automation harness,
// whatever suits their vantage point) behind the same contract.
//
// See examples/probe-server/README.md for build/run/curl examples.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// Request is the JSON body ladon POSTs to the probe endpoint.
type Request struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips,omitempty"`
	Port   int      `json:"port"`
	SNI    string   `json:"sni"`
}

// Response is what ladon expects back. Missing fields are treated as false /
// unset — you only have to fill in the stages you actually performed.
type Response struct {
	DNSOK         bool     `json:"dns_ok"`
	TCPOK         bool     `json:"tcp_ok"`
	TLSOK         bool     `json:"tls_ok"`
	ResolvedIPs   []string `json:"resolved_ips,omitempty"`
	FailureReason string   `json:"reason,omitempty"`
	LatencyMS     int      `json:"latency_ms,omitempty"`
}

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	token := flag.String("token", "", "require Authorization: Bearer <token> if set")
	timeout := flag.Duration("timeout", 2*time.Second, "per-stage probe timeout")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		if *token != "" && r.Header.Get("Authorization") != "Bearer "+*token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Domain == "" {
			http.Error(w, "domain required", http.StatusBadRequest)
			return
		}
		resp := probe(r.Context(), req, *timeout)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("probe-server listening on %s (token=%v)", *listen, *token != "")
	log.Fatal(http.ListenAndServe(*listen, mux))
}

// probe is where operators plug in their own logic. This reference version
// does what ladon's built-in LocalProber does — TCP:443 then TLS-SNI — so
// you can substitute it behind the contract without any ladon change.
func probe(ctx context.Context, req Request, timeout time.Duration) Response {
	started := time.Now()
	r := Response{}

	ips := req.IPs
	if len(ips) == 0 {
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, req.Domain)
		if err != nil {
			r.FailureReason = "dns:" + err.Error()
			r.LatencyMS = int(time.Since(started) / time.Millisecond)
			return r
		}
		for _, a := range resolved {
			if a.IP.To4() == nil {
				continue
			}
			ips = append(ips, a.IP.String())
		}
	}
	r.ResolvedIPs = ips
	r.DNSOK = len(ips) > 0
	if !r.DNSOK {
		r.FailureReason = "dns:no_a_records"
		r.LatencyMS = int(time.Since(started) / time.Millisecond)
		return r
	}

	port := req.Port
	if port == 0 {
		port = 443
	}

	// TCP
	var reachable string
	for _, ip := range ips {
		d := net.Dialer{Timeout: timeout}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(port)))
		if err == nil {
			conn.Close()
			reachable = ip
			break
		}
		r.FailureReason = "tcp:" + err.Error()
	}
	if reachable == "" {
		r.LatencyMS = int(time.Since(started) / time.Millisecond)
		return r
	}
	r.TCPOK = true

	// TLS with SNI, no cert verify (engine wants reachability, not trust).
	sni := req.SNI
	if sni == "" {
		sni = req.Domain
	}
	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp",
		net.JoinHostPort(reachable, fmt.Sprint(port)),
		&tls.Config{ServerName: sni, InsecureSkipVerify: true}) // #nosec G402
	if err != nil {
		r.FailureReason = "tls:" + err.Error()
	} else {
		tlsConn.Close()
		r.TLSOK = true
		r.FailureReason = ""
	}
	r.LatencyMS = int(time.Since(started) / time.Millisecond)
	return r
}
