// Package engine wires all pipeline stages (tail → ingest → probe → decide)
// into a single long-running process.
package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/belotserkovtsev/split-engine/internal/decision"
	"github.com/belotserkovtsev/split-engine/internal/dnsmasq"
	"github.com/belotserkovtsev/split-engine/internal/etld"
	"github.com/belotserkovtsev/split-engine/internal/ipset"
	"github.com/belotserkovtsev/split-engine/internal/manual"
	"github.com/belotserkovtsev/split-engine/internal/prober"
	"github.com/belotserkovtsev/split-engine/internal/publisher"
	"github.com/belotserkovtsev/split-engine/internal/scorer"
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
	IpsetName        string        // name of the ipset to reconcile (empty → disabled)
	IpsetInterval    time.Duration // ipset reconcile cadence
	DNSFreshness     time.Duration // how recent a dns_cache entry must be to ship IPs to ipset
	Scorer           scorer.Config // hot → cache promotion settings
	ManualAllowPath  string        // optional path to manual allow list file
	ManualDenyPath   string        // optional path to manual deny list file
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
		IpsetName:       "prod",
		IpsetInterval:   5 * time.Second,
		DNSFreshness:    6 * time.Hour,
		Scorer:          scorer.Defaults(),
		ManualAllowPath: "",
		ManualDenyPath:  "",
		IgnorePeer:      "10.10.0.1",
	}
}

// Run starts all pipeline stages and blocks until ctx is cancelled.
func Run(ctx context.Context, store *storage.Store, cfg Config) error {
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

	errCh := make(chan error, 6)

	go func() { errCh <- runTailer(ctx, store, cfg) }()
	go func() { errCh <- runProbeWorker(ctx, store, cfg) }()
	go func() { errCh <- runExpirySweeper(ctx, store, cfg) }()
	go func() { errCh <- runPublisher(ctx, store, cfg) }()
	go func() { errCh <- runIpsetSyncer(ctx, store, cfg) }()
	go func() { errCh <- scorer.Run(ctx, store, cfg.Scorer) }()

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
				// Honour the manual deny list — skip ingest entirely so the
				// domain never reaches probes or hot_entries.
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
			case dnsmasq.Reply:
				// Target is the answer: an IP, <CNAME>, NODATA-IPv6, NXDOMAIN, etc.
				// Only IPs go into dns_cache.
				if net.ParseIP(ev.Target) == nil {
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
		// Prefer IPs that dnsmasq actually handed to the client over our own
		// system-resolver answer — avoids engine/client view mismatch with
		// CDNs that geo-route (Meta, Cloudflare, Akamai).
		freshSince := time.Now().UTC().Add(-6 * time.Hour)
		ips, err := store.LookupIPs(ctx, d.Domain, freshSince)
		if err != nil {
			log.Printf("lookup ips %q: %v", d.Domain, err)
		}
		var res prober.Result
		if len(ips) > 0 {
			res = prober.ProbeIPs(ctx, d.Domain, ips, cfg.ProbeTimeout)
		} else {
			// Fallback: no cached client resolution yet — probe with system DNS.
			res = prober.Probe(ctx, d.Domain, cfg.ProbeTimeout)
		}

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

// runIpsetSyncer keeps the gateway-side ipset (e.g. "prod") in sync with
// hot_entries ∪ (later) cache ∪ manual. Each tick: read live hot domains →
// expand to IPs via dns_cache → reconcile set membership.
func runIpsetSyncer(ctx context.Context, store *storage.Store, cfg Config) error {
	if cfg.IpsetName == "" {
		return nil
	}
	mgr := ipset.New(cfg.IpsetName)

	// Don't bother starting if the set doesn't exist — this is an operator
	// concern and silently creating a set could mask misconfiguration.
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

		// Union of all "must-tunnel" sources. Dedupe along the way because
		// one domain can sit in multiple lists (e.g. hot + just-promoted-cache).
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

		// Count confirmed-blocked siblings per eTLD+1 (hot + cache; manual
		// allow doesn't count as blocking evidence, just explicit routing).
		// Aggregation needs ≥2 confirmations to avoid over-tunneling on
		// generic eTLDs (amazonaws.com, googleapis.com).
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
