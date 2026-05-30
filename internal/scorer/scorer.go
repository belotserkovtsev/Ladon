// Package scorer promotes hot domains into cache once enough blocked verdicts
// accumulate. Cache entries have no TTL and survive the 24h hot_entries expiry
// sweep — engine will keep tunneling them until the operator clears them or a
// future re-probe (Phase 7) reverses the call.
package scorer

import (
	"context"
	"log"
	"time"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

// Config tunes promotion thresholds.
type Config struct {
	Interval         time.Duration // how often the scorer wakes up
	Window           time.Duration // verdicts outside this window are ignored
	PromoteThreshold int           // minimum blocked verdicts required in window
}

// Defaults returns production-grade values: scan every 10 minutes, look at
// the last 24 hours of probes, promote only when ≥50 cycles concluded blocked.
// With cooldown=5m the same domain can't be probed more than ~288 times per
// day, so 50 blocked verdicts naturally imply 4+ hours of persistent blocking
// — enough to rule out transient network blips or one-off CDN hiccups.
// Hot_entries (24h TTL) keeps shorter-lived blocks tunneled in the meantime.
func Defaults() Config {
	return Config{
		Interval:         10 * time.Minute,
		Window:           24 * time.Hour,
		PromoteThreshold: 50,
	}
}

// Run is a long-running goroutine. Cancel ctx to stop.
func Run(ctx context.Context, store *storage.Store, cfg Config) error {
	if cfg.PromoteThreshold <= 0 {
		cfg.PromoteThreshold = 3
	}
	if cfg.Window <= 0 {
		cfg.Window = 24 * time.Hour
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 10 * time.Minute
	}

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	promote := func() {
		now := time.Now().UTC()
		since := now.Add(-cfg.Window)

		hots, err := store.ListHotEntries(ctx, now)
		if err != nil {
			log.Printf("scorer: list hot: %v", err)
			return
		}
		promoted := 0
		for _, d := range hots {
			blocks, err := store.CountBlockedVerdicts(ctx, d, since)
			if err != nil {
				log.Printf("scorer: count verdicts %q: %v", d, err)
				continue
			}
			if blocks < cfg.PromoteThreshold {
				continue
			}
			if err := store.PromoteCache(ctx, d, "repeated_block", now); err != nil {
				log.Printf("scorer: promote %q: %v", d, err)
				continue
			}
			promoted++
		}
		if promoted > 0 {
			log.Printf("scorer: promoted %d hot → cache (window=%s threshold=%d)",
				promoted, cfg.Window, cfg.PromoteThreshold)
		}
	}

	promote() // initial pass so newly-started engine doesn't wait a full interval

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			promote()
		}
	}
}
