// Package engine wires all pipeline stages (tail → ingest → probe → decide)
// into a single long-running process.
package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/belotserkovtsev/ladon/internal/decision"
	"github.com/belotserkovtsev/ladon/internal/dnsmasq"
	"github.com/belotserkovtsev/ladon/internal/etld"
	"github.com/belotserkovtsev/ladon/internal/ipset"
	"github.com/belotserkovtsev/ladon/internal/manual"
	"github.com/belotserkovtsev/ladon/internal/prober"
	"github.com/belotserkovtsev/ladon/internal/publisher"
	"github.com/belotserkovtsev/ladon/internal/scorer"
	"github.com/belotserkovtsev/ladon/internal/storage"
	"github.com/belotserkovtsev/ladon/internal/tail"
	"github.com/belotserkovtsev/ladon/internal/watcher"
)

// Config holds runtime knobs.
type Config struct {
	LogPath                string        // dnsmasq log to follow
	FromStart              bool          // tail from beginning of file
	ProbeInterval          time.Duration // how often probe worker wakes up
	ProbeBatch             int           // how many candidates per wake
	ProbeTimeout           time.Duration // per-stage probe timeout
	ProbeCooldown          time.Duration // how long before re-probing a domain
	InlineProbeConcurrency int           // max concurrent inline probes (0 disables inline fast-path)
	HotTTL                 time.Duration // lifetime of a hot_entries row
	ExpiryInterval         time.Duration // hot_entries sweep cadence
	PublishPath            string        // where to write the published domain set
	PublishInterval        time.Duration // publisher cadence
	IpsetName              string        // name of the ipset to reconcile (empty → disabled)
	IpsetInterval          time.Duration // ipset reconcile cadence (periodic safety sweep)
	DNSFreshness           time.Duration // how recent a dns_cache entry must be to ship IPs to ipset
	Scorer                 scorer.Config // hot → cache promotion settings
	ManualAllowPath        string        // optional path to manual allow list file
	ManualDenyPath         string        // optional path to manual deny list file
	IgnorePeer             string        // peer IP to skip (gateway self, etc.)
	Prober                 prober.Prober // probe backend (defaults to LocalProber)
}

// Defaults returns a reasonable baseline config.
func Defaults(logPath string) Config {
	return Config{
		LogPath:                logPath,
		ProbeInterval:          2 * time.Second,
		ProbeBatch:             4,
		ProbeTimeout:           800 * time.Millisecond,
		ProbeCooldown:          5 * time.Minute,
		InlineProbeConcurrency: 8,
		HotTTL:                 24 * time.Hour,
		ExpiryInterval:         30 * time.Second,
		PublishPath:            "state/published-domains.txt",
		PublishInterval:        10 * time.Second,
		IpsetName:              "prod",
		IpsetInterval:          30 * time.Second, // fallback safety sweep; Hot events trigger immediate syncs
		DNSFreshness:           6 * time.Hour,
		Scorer:                 scorer.Defaults(),
		ManualAllowPath:        "",
		ManualDenyPath:         "",
		IgnorePeer:             "10.10.0.1",
	}
}

// Run starts all pipeline stages and blocks until ctx is cancelled.
func Run(ctx context.Context, store *storage.Store, cfg Config) error {
	if cfg.Prober == nil {
		cfg.Prober = prober.NewLocal(cfg.ProbeTimeout)
	}
	log.Printf("probe backend: %s", cfg.Prober.Name())
	// Seed manual lists (best-effort — missing files are fine).
	if n, err := manual.Load(ctx, store, cfg.ManualAllowPath, "allow"); err != nil {
		log.Printf("manual allow load: %v", err)
	} else if n > 0 {
		log.Printf("manual allow: loaded %d entries from %s", n, cfg.ManualAllowPath)
	}
	if n, err := manual.Load(ctx, store, cfg.ManualDenyPath, "deny"); err != nil {
		log.Printf("manual deny load: %v", err)
	} else if n > 0 {
		log.Printf("manual deny: loaded %d entries from %s", n, cfg.ManualDenyPath)
	}

	// Inline probe semaphore caps concurrent fast-path probes from the tailer.
	// Regular probe-worker remains for re-probes and semaphore-full fallback.
	sem := make(chan struct{}, max(1, cfg.InlineProbeConcurrency))

	// Buffered 1 so hot-probe senders never block. Drain-and-sync is idempotent;
	// a single buffered slot coalesces storms of hot events into one sync pass.
	ipsetTrigger := make(chan struct{}, 1)

	errCh := make(chan error, 6)

	go func() { errCh <- runTailer(ctx, store, cfg, sem, ipsetTrigger) }()
	go func() { errCh <- runProbeWorker(ctx, store, cfg, ipsetTrigger) }()
	go func() { errCh <- runExpirySweeper(ctx, store, cfg) }()
	go func() { errCh <- runPublisher(ctx, store, cfg) }()
	go func() { errCh <- runIpsetSyncer(ctx, store, cfg, ipsetTrigger) }()
	go func() { errCh <- scorer.Run(ctx, store, cfg.Scorer) }()

	<-ctx.Done()
	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			return err
		}
	default:
	}
	return ctx.Err()
}

func runTailer(ctx context.Context, store *storage.Store, cfg Config, sem chan struct{}, ipsetTrigger chan<- struct{}) error {
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
			if !parsed {
				skipped++
				continue
			}
			switch ev.Action {
			case dnsmasq.Query:
				if ev.Peer == "" || ev.Peer == cfg.IgnorePeer {
					skipped++
					continue
				}
				if deny, _ := store.IsInDenyList(ctx, ev.Domain, etld.Compute(ev.Domain)); deny {
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
				// Inline probe fast-path: kick off right after ingest so a
				// freshly-observed blocked domain lands in the ipset within
				// sub-second, not after the next probe-worker tick.
				tryInlineProbe(ctx, store, cfg, ev.Domain, sem, ipsetTrigger)
			case dnsmasq.Reply:
				parsed := net.ParseIP(ev.Target)
				// We operate on v4 only — stun0, WG subnet, iptables rules
				// and the prod ipset are all v4. v6 answers would just create
				// probe-time "cannot assign" failures and pollute dns_cache.
				if parsed == nil || parsed.To4() == nil {
					skipped++
					continue
				}
				if err := store.UpsertDNSObservation(ctx, ev.Domain, ev.Target, time.Time{}); err != nil {
					log.Printf("dns_cache %q→%s: %v", ev.Domain, ev.Target, err)
					continue
				}
			default:
				skipped++
			}
		case <-report.C:
			log.Printf("tailer: ingested=%d skipped=%d", ingested, skipped)
		}
	}
}

// tryInlineProbe kicks an immediate probe in a goroutine when the semaphore
// has room. If the semaphore is full we simply drop the fast-path attempt —
// the regular probe-worker ticks will pick the domain up shortly after, so
// nothing is lost, we just don't beat the worker to it under heavy load.
func tryInlineProbe(ctx context.Context, store *storage.Store, cfg Config, domain string, sem chan struct{}, ipsetTrigger chan<- struct{}) {
	if cap(sem) == 0 || cfg.InlineProbeConcurrency == 0 {
		return
	}
	select {
	case sem <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-sem }()
		eligible, err := store.ProbeEligible(ctx, domain, time.Now().UTC())
		if err != nil || !eligible {
			return
		}
		probeDomain(ctx, store, cfg, domain, ipsetTrigger)
	}()
}

func runProbeWorker(ctx context.Context, store *storage.Store, cfg Config, ipsetTrigger chan<- struct{}) error {
	ticker := time.NewTicker(cfg.ProbeInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := probeOnce(ctx, store, cfg, ipsetTrigger); err != nil {
				log.Printf("probe tick: %v", err)
			}
		}
	}
}

func probeOnce(ctx context.Context, store *storage.Store, cfg Config, ipsetTrigger chan<- struct{}) error {
	now := time.Now().UTC()
	candidates, err := store.ListProbeCandidates(ctx, cfg.ProbeBatch, now)
	if err != nil {
		return err
	}
	for _, d := range candidates {
		if err := ctx.Err(); err != nil {
			return nil
		}
		probeDomain(ctx, store, cfg, d.Domain, ipsetTrigger)
	}
	return nil
}

// probeDomain runs one full probe→decision→persist cycle for a single domain.
// Shared by the batch worker and the inline fast-path from the tailer.
func probeDomain(ctx context.Context, store *storage.Store, cfg Config, domain string, ipsetTrigger chan<- struct{}) {
	if err := prober.Validate(domain); err != nil {
		_ = store.SetDomainState(ctx, domain, "ignore", time.Time{})
		return
	}
	// Prefer IPs that dnsmasq actually handed to the client — avoids engine/
	// client view mismatch with CDNs that geo-route.
	freshSince := time.Now().UTC().Add(-cfg.DNSFreshness)
	ips, err := store.LookupIPs(ctx, domain, freshSince)
	if err != nil {
		log.Printf("lookup ips %q: %v", domain, err)
	}
	res := cfg.Prober.Probe(ctx, domain, ips)

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
		log.Printf("persist probe %q: %v", domain, err)
		return
	}

	verdict := decision.Classify(res)
	cooldown := time.Now().UTC().Add(cfg.ProbeCooldown)

	switch verdict {
	case decision.Hot:
		if err := store.SetDomainState(ctx, domain, "hot", cooldown); err != nil {
			log.Printf("set state hot %q: %v", domain, err)
		}
		if err := store.UpsertHotEntry(ctx, domain,
			reasonFromProbe(res), time.Now().UTC().Add(cfg.HotTTL)); err != nil {
			log.Printf("upsert hot %q: %v", domain, err)
		}
		log.Printf("probe %s → HOT (%s, %dms)", domain, res.FailureReason, res.LatencyMS)
		// Nudge the ipset syncer — a new IP may now need to be tunneled.
		select {
		case ipsetTrigger <- struct{}{}:
		default:
		}
	case decision.Ignore:
		if err := store.SetDomainState(ctx, domain, "ignore", cooldown); err != nil {
			log.Printf("set state ignore %q: %v", domain, err)
		}
	default:
		if err := store.SetDomainState(ctx, domain, "watch", cooldown); err != nil {
			log.Printf("set state watch %q: %v", domain, err)
		}
	}
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
	publishNow()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			publishNow()
		}
	}
}

// runIpsetSyncer keeps the gateway-side ipset (e.g. "prod") in sync with
// hot_entries ∪ cache_entries ∪ manual-allow. Triggered both by a periodic
// safety ticker and by the ipsetTrigger channel — hot probes signal the
// channel so a just-observed blocked IP lands in `prod` within ~milliseconds.
func runIpsetSyncer(ctx context.Context, store *storage.Store, cfg Config, trigger <-chan struct{}) error {
	if cfg.IpsetName == "" {
		return nil
	}
	mgr := ipset.New(cfg.IpsetName)

	ok, err := mgr.Exists(ctx)
	if err != nil {
		log.Printf("ipset exists check %q: %v", cfg.IpsetName, err)
		return nil
	}
	if !ok {
		log.Printf("ipset %q not found — skipping ipset syncer; create it with `ipset create %s hash:ip`", cfg.IpsetName, cfg.IpsetName)
		return nil
	}

	ticker := time.NewTicker(cfg.IpsetInterval)
	defer ticker.Stop()

	syncNow := func() {
		now := time.Now().UTC()
		freshSince := now.Add(-cfg.DNSFreshness)

		hots, err := store.ListHotEntries(ctx, now)
		if err != nil {
			log.Printf("ipset: list hot: %v", err)
			return
		}
		cache, err := store.ListCacheEntries(ctx)
		if err != nil {
			log.Printf("ipset: list cache: %v", err)
		}
		allow, err := store.ListManualByList(ctx, "allow")
		if err != nil {
			log.Printf("ipset: list allow: %v", err)
		}

		sources := make([]string, 0, len(hots)+len(cache)+len(allow))
		seenSrc := map[string]struct{}{}
		for _, d := range hots {
			if _, ok := seenSrc[d]; ok {
				continue
			}
			seenSrc[d] = struct{}{}
			sources = append(sources, d)
		}
		for _, d := range cache {
			if _, ok := seenSrc[d]; ok {
				continue
			}
			seenSrc[d] = struct{}{}
			sources = append(sources, d)
		}
		for _, d := range allow {
			if _, ok := seenSrc[d]; ok {
				continue
			}
			seenSrc[d] = struct{}{}
			sources = append(sources, d)
		}

		confirmedByETLD := map[string]int{}
		for _, d := range hots {
			if r := etld.Compute(d); r != "" {
				confirmedByETLD[r]++
			}
		}
		for _, d := range cache {
			if r := etld.Compute(d); r != "" {
				confirmedByETLD[r]++
			}
		}

		desired := map[string]struct{}{}
		expandedETLDs := map[string]struct{}{}
		for _, d := range sources {
			ips, err := store.LookupIPs(ctx, d, freshSince)
			if err != nil {
				log.Printf("ipset: lookup ips %q: %v", d, err)
				continue
			}
			for _, ip := range ips {
				desired[ip] = struct{}{}
			}
			root := etld.Compute(d)
			if root == "" || confirmedByETLD[root] < 2 {
				continue
			}
			if _, done := expandedETLDs[root]; done {
				continue
			}
			expandedETLDs[root] = struct{}{}
			siblingIPs, err := store.LookupIPsByETLD(ctx, root, freshSince)
			if err != nil {
				log.Printf("ipset: lookup etld %q: %v", root, err)
				continue
			}
			for _, ip := range siblingIPs {
				desired[ip] = struct{}{}
			}
		}
		list := make([]string, 0, len(desired))
		for ip := range desired {
			list = append(list, ip)
		}
		added, removed, err := mgr.Reconcile(ctx, list)
		if err != nil {
			log.Printf("ipset reconcile: %v", err)
			return
		}
		if added > 0 || removed > 0 {
			log.Printf("ipset %s: +%d -%d (total %d, etlds expanded %d)",
				cfg.IpsetName, added, removed, len(list), len(expandedETLDs))
		}
	}
	syncNow()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			syncNow()
		case <-trigger:
			syncNow()
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
