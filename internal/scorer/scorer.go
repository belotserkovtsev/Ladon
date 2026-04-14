// Package scorer accumulates evidence and promotes stable domains from hot to cache.
//
// This is a stub. Real logic lands in Phase 4.
package scorer

import "github.com/belotserkovtsev/split-engine/internal/storage"

// Compute returns a long-term confidence score for promotion into cache.
// Currently always returns 0.
func Compute(_ storage.Domain, _ []storage.ProbeResult) float64 {
	return 0
}
