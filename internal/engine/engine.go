// Package engine wires all pipeline stages (tail → ingest → probe → decide)
// into a single long-running process.
package engine

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/belotserkovtsev/split-engine/internal/decision"
	"github.com/belotserkovtsev/split-engine/internal/dnsmasq"
	"github.com/belotserkovtsev/split-engine/internal/prober"
	"github.com/belotserkovtsev/split-engine/internal/publisher"
	"github.com/belotserkovtsev/split-engine/internal/storage"
	"github.com/belotserkovtsev/split-engine/internal/tail"
	"github.com/belotserkovtsev/split-engine/internal/watcher"
)

// Config holds runtime knobs.
type Config struct {
	LogPath          string        // dnsmasq log to follow
	FromStart        bool          // tail from beginning of file
	ProbeInterval    time.Duration // how often probe worker wakes up
	ProbeBatch       int           // how many candidates per wake
	ProbeTimeout     time.Duration // per-stage probe timeout
	ProbeCooldown    time.Duration // how long before re-probing a domain
	HotTTL           time.Duration // lifetime of a hot_entries row
	ExpiryInterval   time.Duration // hot_entries sweep cadence
	PublishPath      string        // where to write the published domain set
	PublishInterval  time.Duration // publisher cadence
	IgnorePeer       string        // peer IP to skip (gateway self, etc.)
}

// Defaults returns a reasonable baseline config.
func Defaults(logPath string) Config {
	return Config{
		LogPath:         logPath,
		ProbeInterval:   2 * time.Second,
		ProbeBatch:      4,
		ProbeTimeout:    2 * time.Second,
		ProbeCooldown:   5 * time.Minute,
		HotTTL:          24 * time.Hour,
		ExpiryInterval:  30 * time.Second,
		PublishPath:     "state/published-domains.txt",
		PublishInterval: 10 * time.Second,
		IgnorePeer:      "10.10.0.1",
	}
}

// Run starts all pipeline stages and blocks until ctx is cancelled.
func Run(ctx context.Context, store *storage.Store, cfg Config) error {
	errCh := make(chan error, 4)

	go func() { errCh <- runTailer(ctx, store, cfg) }()
	go func() { errCh <- runProbeWorker(ctx, store, cfg) }()
	go func() { errCh <- runExpirySweeper(ctx, store, cfg) }()
	go func() { errCh <- runPublisher(ctx, store, cfg) }()

	<-ctx.Done()
	// Drain one error if any stage exited early with an actual error.
	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return err
		}
	default:
	}
	return ctx.Err()
}

func runTailer(ctx context.Context, store *storage.Store, cfg Config) error {
	lines, errs := tail.Follow(ctx, cfg.LogPath, tail.Options{StartAtEnd: !cfg.FromStart})
	ingested, skipped := 0, 0
	report := time.NewTicker(30 * time.Second)
	defer report.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err, ok := <-errs:
			if ok && err != nil {
				return fmt.Errorf("tail: %w", err)
			}
		case line, ok := <-lines:
			if !ok {
				return nil
			}
			ev, parsed := dnsmasq.Parse(line)
			if !parsed || ev.Action != dnsmasq.Query {
				skipped++
				continue
			}
			if ev.Peer == "" || ev.Peer == cfg.IgnorePeer {
				skipped++
				continue
			}
			if _, err := watcher.Ingest(ctx, store, watcher.Event{
				Domain: ev.Domain,
				Peer:   ev.Peer,
			}); err != nil {
				log.Printf("ingest %q: %v", ev.Domain, err)
				continue
			}
			ingested++
		case <-report.C:
			log.Printf("tailer: ingested=%d skipped=%d", ingested, skipped)
		}
	}
}

func runProbeWorker(ctx context.Context, store *storage.Store, cfg Config) error {
	ticker := time.NewTicker(cfg.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := probeOnce(ctx, store, cfg); err != nil {
				log.Printf("probe tick: %v", err)
			}
		}
	}
}

func probeOnce(ctx context.Context, store *storage.Store, cfg Config) error {
	now := time.Now().UTC()
	candidates, err := store.ListProbeCandidates(ctx, cfg.ProbeBatch, now)
	if err != nil {
		return err
	}
	for _, d := range candidates {
		if err := ctx.Err(); err != nil {
			return nil
		}
		if err := prober.Validate(d.Domain); err != nil {
			// Mark invalid domains as ignore so they stop cycling.
			_ = store.SetDomainState(ctx, d.Domain, "ignore", time.Time{})
			continue
		}
		res := prober.Probe(ctx, d.Domain, cfg.ProbeTimeout)

		dns, tcp, tls := res.DNSOK, res.TCPOK, res.TLSOK
		if _, err := store.InsertProbe(ctx, storage.ProbeResult{
			Domain:        res.Domain,
			DNSOK:         &dns,
			TCPOK:         &tcp,
			TLSOK:         &tls,
			HTTPOK:        res.HTTPOK,
			ResolvedIPs:   res.ResolvedIPs,
			FailureReason: res.FailureReason,
			LatencyMS:     res.LatencyMS,
		}, time.Time{}); err != nil {
			log.Printf("persist probe %q: %v", d.Domain, err)
			continue
		}

		verdict := decision.Classify(res)
		cooldown := time.Now().UTC().Add(cfg.ProbeCooldown)

		switch verdict {
		case decision.Hot:
			if err := store.SetDomainState(ctx, d.Domain, "hot", cooldown); err != nil {
				log.Printf("set state hot %q: %v", d.Domain, err)
			}
			if err := store.UpsertHotEntry(ctx, d.Domain,
				reasonFromProbe(res), time.Now().UTC().Add(cfg.HotTTL)); err != nil {
				log.Printf("upsert hot %q: %v", d.Domain, err)
			}
			log.Printf("probe %s → HOT (%s, %dms)", d.Domain, res.FailureReason, res.LatencyMS)
		case decision.Ignore:
			// Keep ignore terminal for now; a stable direct path doesn't need re-checking often.
			// We still set cooldown so that new observations don't re-queue immediately.
			if err := store.SetDomainState(ctx, d.Domain, "ignore", cooldown); err != nil {
				log.Printf("set state ignore %q: %v", d.Domain, err)
			}
		default:
			if err := store.SetDomainState(ctx, d.Domain, "watch", cooldown); err != nil {
				log.Printf("set state watch %q: %v", d.Domain, err)
			}
		}
	}
	return nil
}

func reasonFromProbe(r prober.Result) string {
	if r.FailureReason != "" {
		return r.FailureReason
	}
	return "hot"
}

func runPublisher(ctx context.Context, store *storage.Store, cfg Config) error {
	if cfg.PublishPath == "" {
		return nil
	}
	ticker := time.NewTicker(cfg.PublishInterval)
	defer ticker.Stop()

	publishNow := func() {
		n, err := publisher.PublishDomains(ctx, store, cfg.PublishPath)
		if err != nil {
			log.Printf("publish: %v", err)
			return
		}
		log.Printf("published %d domains → %s", n, cfg.PublishPath)
	}
	publishNow() // initial publish so consumer sees something on startup

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			publishNow()
		}
	}
}

func runExpirySweeper(ctx context.Context, store *storage.Store, cfg Config) error {
	ticker := time.NewTicker(cfg.ExpiryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			n, err := store.ExpireHotEntries(ctx, time.Now().UTC())
			if err != nil {
				log.Printf("expire hot: %v", err)
				continue
			}
			if n > 0 {
				log.Printf("expired %d hot entries", n)
			}
		}
	}
}
