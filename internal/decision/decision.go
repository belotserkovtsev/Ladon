// Package decision classifies probe outcomes into engine states.
//
// Current policy (Phase 2, intentionally crude):
//
//	DNS failed              → Ignore  (domain doesn't resolve — not ours)
//	TCP:443 failed          → Hot     (reachable name, unreachable host → likely blocked)
//	TLS handshake failed    → Hot     (TLS interception / blackhole → likely blocked)
//	Everything OK           → Ignore  (direct path works — no need to tunnel)
//
// We'll refine these rules in Phase 4 (scorer) once we have repeated evidence.
package decision

import "github.com/belotserkovtsev/split-engine/internal/prober"

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
	return Ignore
}
