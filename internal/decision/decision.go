// Package decision classifies probe outcomes into engine states.
//
// Current policy:
//
//	DNS failed              → Ignore  (domain doesn't resolve — not ours)
//	TCP:443 failed          → Hot     (reachable name, unreachable host → likely blocked)
//	TLS handshake failed    → Hot     (TLS interception / blackhole → likely blocked)
//	HTTP cutoff             → Hot     (TLS up but stream severed mid-response — L7 DPI signature)
//	Everything OK           → Ignore  (direct path works — no need to tunnel)
//
// HTTPOK is tri-state: nil means the probe didn't run the HTTP stage (older
// remote prober, manual call site that skipped) — fall back to TCP+TLS
// verdict only. ptr(false) means we tried and got severed; ptr(true) means
// we read a real response.
package decision

import "github.com/belotserkovtsev/ladon/internal/prober"

type Verdict string

const (
	Ignore Verdict = "ignore"
	Watch  Verdict = "watch"
	Hot    Verdict = "hot"
)

// Classify maps a probe result to a verdict.
func Classify(r prober.Result) Verdict {
	if !r.DNSOK {
		return Ignore
	}
	if !r.TCPOK || !r.TLSOK {
		return Hot
	}
	if r.HTTPOK != nil && !*r.HTTPOK {
		return Hot
	}
	return Ignore
}
