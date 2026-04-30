package decision

import (
	"strings"

	"github.com/belotserkovtsev/ladon/internal/prober"
)

// RemoteState classifies the remote prober's result for exit-compare combine.
// The five outcomes give the combiner enough resolution to distinguish a
// genuine DPI block (local fail + remote ok) from server-side severing
// (local fail + remote also fails at HTTP) — the latter is the Yandex-class
// FP that today's combine misses by checking only TCP+TLS layers.
type RemoteState int

const (
	// RemoteOK — TCP+TLS+HTTP all succeeded on the remote vantage point.
	// Solid confirmation that the target is reachable; a local failure
	// here is real DPI.
	RemoteOK RemoteState = iota

	// RemoteTCPTLSOnly — TCP+TLS succeeded but HTTP stage didn't run
	// (HTTPOK==nil). Happens with legacy probe-servers that predate the
	// probe-v2 HTTP-cutoff stage. Treated as "weak ok": enough to confirm
	// TCP/TLS-class DPI but not HTTP-class (could be server-side severing).
	RemoteTCPTLSOnly

	// RemoteHTTPFail — TCP+TLS succeeded but HTTP stage failed (HTTPOK==false).
	// Both vantage points see HTTP-stream-severed → server-side, not DPI.
	// This is the missing branch in the pre-PR combine logic.
	RemoteHTTPFail

	// RemoteFail — TCP or TLS layer failed on remote. Methodological FP
	// (port wrong, dead server, geofence on both vantages, transient
	// outage). Either way: not a clean DPI signal.
	RemoteFail

	// RemoteUnavailable — the remote prober itself was unreachable
	// (network error, timeout, non-200). No verdict from remote;
	// fall back to local opinion.
	RemoteUnavailable
)

// ClassifyRemote maps a prober.Result returned by the remote prober into a
// RemoteState. Mirrors engine.isRemoteTransportFailure for the legacy-prefix
// fallback path (older remotes that only set "remote:..." reason without
// FailureCode).
func ClassifyRemote(r prober.Result) RemoteState {
	if r.IsRemoteTransportFailure() || strings.HasPrefix(r.FailureReason, "remote:") {
		return RemoteUnavailable
	}
	if !r.TCPOK || !r.TLSOK {
		return RemoteFail
	}
	if r.HTTPOK == nil {
		return RemoteTCPTLSOnly
	}
	if !*r.HTTPOK {
		return RemoteHTTPFail
	}
	return RemoteOK
}

// CombineExitCompare folds local FailureCode and RemoteState into the final
// verdict for the exit-compare batch path. Called only when local already
// classified to Hot — Ignore-from-local short-circuits before reaching here,
// and remote can't override "local says reachable" anyway.
//
// The tag string is appended to hot_entries.reason for observability so the
// operator can grep which combine branch produced any given verdict.
func CombineExitCompare(localCode prober.FailureCode, remote RemoteState) (Verdict, string) {
	switch remote {
	case RemoteUnavailable:
		// Safe default: keep the local Hot verdict so a probe-server
		// outage doesn't cascade into Ignore-ing real DPI blocks.
		return Hot, "remote:unavailable"

	case RemoteHTTPFail:
		// Both vantages got past TCP+TLS but HTTP stage severed on both
		// → server-side anti-bot / rate-limit / geo-block / WAF, not DPI.
		// Yandex Music backends (ynison.music.yandex.net,
		// api.messenger.yandex.net) reproduce this consistently from any
		// commercial-hosting AS — local at AS9123 Timeweb gets
		// http_cutoff, remote at the orchestrator AS gets http_cutoff
		// too. Pre-PR combine looked only at TCP+TLS and false-promoted
		// these to Hot.
		return Ignore, "remote:http_fail"

	case RemoteFail:
		// Both probers see real failure: dead server, wrong port,
		// symmetric geofence. Not our problem.
		return Ignore, "remote:fail"

	case RemoteOK:
		// Full chain succeeded on remote — solid confirmation that the
		// target is reachable from clean vantage points and the local
		// failure is real DPI. Promote to Hot regardless of local code
		// class.
		return Hot, "remote:ok"

	case RemoteTCPTLSOnly:
		// Legacy remote that doesn't run HTTP stage. For TCP/TLS-class
		// DPI codes (refused/reset/timeout/handshake-timeout/etc.) the
		// TCP+TLS layer evidence is sufficient — that's where the block
		// happens. For HTTP-class ambiguous codes (cutoff/timeout/error)
		// we can't distinguish DPI from server-side severing without an
		// HTTP-stage answer; conservatively downgrade to Ignore to avoid
		// the Yandex-class FP.
		if isAmbiguousCode(localCode) {
			return Ignore, "remote:tcp+tls-only|local:ambig"
		}
		return Hot, "remote:tcp+tls-ok"
	}
	return Ignore, "remote:unknown"
}

// isAmbiguousCode reports whether a FailureCode could plausibly come from
// either DPI or a server-side defense (anti-bot, rate-limit, geo-WAF). These
// codes need stronger remote evidence (full HTTP-stage success) to confirm
// DPI; lacking that, exit-compare downgrades them to Ignore.
//
// All three live at the HTTP layer of the staged probe — that's exactly
// where server-side severing manifests. TCP/TLS-layer codes don't have
// this ambiguity: a TCP RST or TLS handshake-timeout from a residential
// or datacenter IP almost always indicates middlebox interference.
func isAmbiguousCode(c prober.FailureCode) bool {
	switch c {
	case prober.CodeHTTPCutoff, prober.CodeHTTPTimeout, prober.CodeHTTPError:
		return true
	}
	return false
}

// isHighConfDPICode reports whether a FailureCode strongly indicates DPI
// when the local probe fails. Currently informational only — the combine
// matrix collapses it into "not ambiguous" — but kept exported for callers
// (scorer, telemetry) that may want stage-aware behavior.
func isHighConfDPICode(c prober.FailureCode) bool {
	switch c {
	case prober.CodeTCPRefused, prober.CodeTCPReset, prober.CodeTCPTimeout,
		prober.CodeTCPUnreachable, prober.CodeTCPError,
		prober.CodeTLSHandshakeTimeout, prober.CodeTLSEOF,
		prober.CodeTLSReset, prober.CodeTLSError, prober.CodeTLS13Block,
		prober.CodeHTTPReset:
		return true
	}
	return false
}
