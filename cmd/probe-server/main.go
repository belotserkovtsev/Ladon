// Package main is the reference probe-server that ladon's RemoteProber
// speaks. It runs the same probe pipeline ladon's LocalProber does (so
// remote and local results stay structurally comparable for exit-compare),
// then surfaces them in the JSON contract documented in docs/probe-api.md.
//
// Operators can replace this with a custom backend (4G SIM, headless
// browser, distant Pi, etc.); they only have to honour the wire-format.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/belotserkovtsev/ladon/internal/prober"
)

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	token := flag.String("token", "", "require Authorization: Bearer <token> if set")
	timeout := flag.Duration("timeout", 2*time.Second, "per-stage probe timeout")
	flag.Parse()

	// Share ladon's probe pipeline so the remote vantage runs identical
	// stages (TCP / TLS-split / HTTP-cutoff). exit-compare in ladon depends
	// on this — divergence between local and remote only makes sense if it
	// comes from the network path, not the probe semantics.
	probeIt := prober.NewLocal(*timeout)

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
		var req prober.RemoteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Domain == "" {
			http.Error(w, "domain required", http.StatusBadRequest)
			return
		}

		result := probeIt.Probe(r.Context(), req.Domain, req.IPs)
		resp := prober.RemoteResponse{
			DNSOK:         result.DNSOK,
			TCPOK:         result.TCPOK,
			TLSOK:         result.TLSOK,
			TLS12OK:       result.TLS12OK,
			TLS13OK:       result.TLS13OK,
			HTTPOK:        result.HTTPOK,
			ResolvedIPs:   result.ResolvedIPs,
			FailureReason: result.FailureReason,
			FailureCode:   string(result.FailureCode),
			LatencyMS:     result.LatencyMS,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("probe-server listening on %s (token=%v, timeout=%s)",
		*listen, *token != "", *timeout)
	log.Fatal(http.ListenAndServe(*listen, mux))
}
