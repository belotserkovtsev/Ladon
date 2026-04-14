// Package decision classifies probe outcomes into engine states.
//
// This is a stub. Real logic (ignore / watch / hot) lands in Phase 2.
package decision

import "github.com/belotserkovtsev/split-engine/internal/prober"

type Verdict string

const (
	Ignore Verdict = "ignore"
	Watch  Verdict = "watch"
	Hot    Verdict = "hot"
)

// Classify maps a probe result to a verdict. Currently always returns Watch.
func Classify(_ prober.Result) Verdict {
	return Watch
}
