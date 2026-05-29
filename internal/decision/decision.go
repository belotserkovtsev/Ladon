// Package decision classifies probe outcomes into a censorship verdict.
//
// A Verdict answers one question — "is this domain blocked?" — and is kept
// deliberately separate from the pipeline state a domain sits in
// (new/watch/hot/cache/ignore). The engine maps verdict→state at a single
// seam (see engine.probeDomain): Blocked→hot, Clear→ignore.
//
// Current policy:
//
//	DNS failed              → Clear    (domain doesn't resolve — not ours)
//	TCP:443 failed          → Blocked  (reachable name, unreachable host → likely blocked)
//	TLS handshake failed    → Blocked  (TLS interception / blackhole → likely blocked)
//	HTTP cutoff             → Blocked  (TLS up but stream severed mid-response — L7 DPI signature)
//	Everything OK           → Clear    (direct path works — no need to tunnel)
//
// HTTPOK is tri-state: nil means the probe didn't run the HTTP stage (older
// remote prober, manual call site that skipped) — fall back to TCP+TLS
// verdict only. ptr(false) means we tried and got severed; ptr(true) means
// we read a real response OR the server actively rejected with a typed
// TLS alert (mTLS challenge etc., handled inside prober — see
// prober.IsServerReachable). Either way the path is reachable, so Clear.
package decision

import "github.com/belotserkovtsev/ladon/internal/prober"

// Verdict is the censorship judgment for one probe cycle: is the domain
// blocked or reachable (clear). It is NOT a pipeline state — the engine
// translates a verdict into a domains.state.
type Verdict string

const (
	Clear   Verdict = "clear"   // path works directly — no block
	Blocked Verdict = "blocked" // DPI/censorship interfering — tunnel it
)

// Classify maps a probe result to a verdict.
func Classify(r prober.Result) Verdict {
	if !r.DNSOK {
		return Clear
	}
	if !r.TCPOK || !r.TLSOK {
		return Blocked
	}
	if r.HTTPOK != nil && !*r.HTTPOK {
		return Blocked
	}
	// 1.3 ClientHello-targeted block: TLSOK is true (the 1.2 fallback
	// succeeded), HTTPOK is true (server responded over 1.2), but the
	// browser the user actually drives speaks 1.3 by default. Treating
	// this as Clear would silently leave the user breaking; treating
	// it as Blocked tunnels via Ladon and keeps Chrome/Firefox 1.3 working.
	if r.FailureCode == prober.CodeTLS13Block {
		return Blocked
	}
	return Clear
}
