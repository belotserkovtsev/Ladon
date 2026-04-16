// Package engine wires all pipeline stages (tail → ingest → probe → decide)
// into a single long-running process.
package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/belotserkovtsev/ladon/internal/decision"
	"github.com/belotserkovtsev/ladon/internal/dnsmasq"
	"github.com/belotserkovtsev/ladon/internal/dnsmasqcfg"
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

// collectManualDomains reads the operator's manual-allow file plus every
// enabled extension, returns a single deduplicated domain list. dnsmasq
// then turns each into an `ipset=/domain/<set>` directive.
func collectManualDomains(cfg Config) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string
	add := func(domains []string) {
		for _, d := range domains {
			if _, ok := seen[d]; ok {
				continue
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}

	if cfg.ManualAllowPath != "" {
		ds, err := manual.ReadDomains(cfg.ManualAllowPath)
		if err != nil {
			return out, fmt.Errorf("manual-allow %q: %w", cfg.ManualAllowPath, err)
		}
		add(ds)
	}
	for _, name := range cfg.Extensions {
		path := filepath.Join(cfg.ExtensionsPath, name+".txt")
		if _, err := os.Stat(path); err != nil {
			log.Printf("extension %q: file not found at %s — check extensions_path", name, path)
			continue
		}
		ds, err := manual.ReadDomains(path)
		if err != nil {
			log.Printf("extension %q read: %v", name, err)
			continue
		}
		log.Printf("extension %s: %d domains from %s", name, len(ds), path)
		add(ds)
	}
	return out, nil
}

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
	IpsetName              string        // engine-managed ipset name (default ladon_engine)
	ManualIpsetName        string        // dnsmasq-managed ipset name (default ladon_manual)
	IpsetInterval          time.Duration // ipset reconcile cadence (periodic safety sweep)
	DNSFreshness           time.Duration // how recent a dns_cache entry must be to ship IPs to ipset
	Scorer                 scorer.Config // hot → cache promotion settings
	ManualAllowPath        string        // optional path to manual allow list file
	ManualDenyPath         string        // optional path to manual deny list file
	IgnorePeer             string        // peer IP to skip (gateway self, etc.)

	// Extensions are bundled allow-list presets (e.g. "ai", "twitch") that
	// ship with ladon and are opt-in by name. Each name resolves to
	// ExtensionsPath/<name>.txt, which is loaded with the same parser as
	// ManualAllowPath. See release/extensions/ for the shipped presets.
	Extensions     []string
	ExtensionsPath string // default "extensions" (relative to WorkingDirectory)

	// LocalProber is the always-on baseline. Used by the inline fast-path from
	// the tailer (where remote round-trips would blow the sub-second latency
	// budget) and as the first stage of the batch worker. Defaults to NewLocal.
	LocalProber prober.Prober

	// RemoteProber is the optional exit-compare validator. When non-nil, the
	// batch worker runs it ONLY after a local FAIL, and uses the combined
	// verdict: local FAIL + remote OK = real DPI block (Hot); local FAIL +
	// remote FAIL = methodological FP (Ignore — port wrong, dead server,
	// geofence on both vantage points). Inline path never uses this.
	RemoteProber prober.Prober
}

// Defaults returns a reasonable baseline config.
func Defaults(logPath string) Config {
	return Config{
		LogPath:                logPath,
		ExtensionsPath:         "extensions",
		ProbeInterval:          2 * time.Second,
		ProbeBatch:             4,
		ProbeTimeout:           800 * time.Millisecond,
		ProbeCooldown:          5 * time.Minute,
		InlineProbeConcurrency: 8,
		HotTTL:                 24 * time.Hour,
		ExpiryInterval:         30 * time.Second,
		PublishPath:            "state/published-domains.txt",
		PublishInterval:        10 * time.Second,
		IpsetName:              "ladon_engine",
		ManualIpsetName:        "ladon_manual",
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
	if cfg.LocalProber == nil {
		cfg.LocalProber = prober.NewLocal(cfg.ProbeTimeout)
	}
	if cfg.RemoteProber != nil {
		log.Printf("probe backends: %s (baseline) + %s (exit-compare)",
			cfg.LocalProber.Name(), cfg.RemoteProber.Name())
	} else {
		log.Printf("probe backend: %s", cfg.LocalProber.Name())
	}
	// Manual-deny still goes through the database — engine consults
	// IsInDenyList during ingest to skip those domains entirely.
	if n, err := manual.Load(ctx, store, cfg.ManualDenyPath, "deny"); err != nil {
		log.Printf("manual deny load: %v", err)
	} else if n > 0 {
		log.Printf("manual deny: loaded %d entries from %s", n, cfg.ManualDenyPath)
	}

	// Manual-allow + extensions are delegated to dnsmasq's native ipset=
	// directive. Reasons for the architectural split:
	//   1. dnsmasq adds resolved IPs to the kernel set BEFORE returning the
	//      DNS answer, so the client's first TCP SYN already finds the IP.
	//      Our tail-and-reconcile loop can never win that race.
	//   2. dnsmasq walks CNAME chains internally — no need for ladon-side
	//      query-id tracking or eTLD+1 expansion to compensate.
	//   3. Manual list = operator's stated intent; doesn't need probe-driven
	//      verification. Letting dnsmasq own it keeps that mental model clean.
	manualDomains, err := collectManualDomains(cfg)
	if err != nil {
		log.Printf("manual: %v", err)
	}
	if cfg.ManualIpsetName != "" {
		if err := dnsmasqcfg.Write(cfg.ManualIpsetName, manualDomains); err != nil {
			log.Printf("dnsmasq config write: %v", err)
		} else {
			log.Printf("manual: wrote %d domains → %s (ipset=%s)", len(manualDomains), dnsmasqcfg.Path, cfg.ManualIpsetName)
			if err := dnsmasqcfg.Reload(ctx); err != nil {
				log.Printf("dnsmasq reload: %v — manual list will activate on next dnsmasq restart", err)
			}
		}
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

	// chainOrigin tracks dnsmasq query-id → the domain the client originally
	// asked for. dnsmasq emits ALL replies in a CNAME chain under the same
	// query-id, but only the terminal A-record carries an IP, and that
	// reply's domain is the LAST hop in the chain (e.g. vercel-dns-013.com
	// for a query against developers.openai.com). Without this map, that IP
	// would land in dns_cache under vercel-dns-013.com — and our manual-allow
	// eTLD+1 expansion of openai.com would never see it. Map size is bounded
	// by the dnsmasq query-id space (~65k); each entry is overwritten when
	// the id wraps around, so no explicit cleanup needed.
	chainOrigin := make(map[string]string)

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
				// Remember the original queried domain — we'll use it to
				// re-attribute IP replies that come back through CNAME hops
				// to a different domain family.
				if ev.QueryID != "" {
					chainOrigin[ev.QueryID] = ev.Domain
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
				// CNAME re-attribution: if we tracked the original query for
				// this id, store the IP under THAT domain so eTLD+1 lookups
				// from manual-allow can find it. Falls back to the raw reply
				// domain when we don't have a record (log started mid-stream).
				storeDomain := ev.Domain
				if origin, ok := chainOrigin[ev.QueryID]; ok && origin != "" {
					storeDomain = origin
				}
				if err := store.UpsertDNSObservation(ctx, storeDomain, ev.Target, time.Time{}); err != nil {
					log.Printf("dns_cache %q→%s: %v", storeDomain, ev.Target, err)
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
		// Inline path: local-only. The exit-compare validator (if configured)
		// runs on the batch worker's cooldown re-probe — it would blow the
		// inline latency budget here.
		probeDomain(ctx, store, cfg, domain, ipsetTrigger, false)
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
		// Batch worker uses exit-compare when RemoteProber is configured —
		// gives the operator's vantage point a vote on borderline calls.
		probeDomain(ctx, store, cfg, d.Domain, ipsetTrigger, true)
	}
	return nil
}

// probeDomain runs one full probe→decision→persist cycle for a single domain.
// Shared by the batch worker and the inline fast-path from the tailer; the
// useExitCompare flag turns on the optional remote validator stage that only
// the batch path opts into.
func probeDomain(ctx context.Context, store *storage.Store, cfg Config, domain string, ipsetTrigger chan<- struct{}, useExitCompare bool) {
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

	// Phase 1: local probe (always). This is the gateway-side view; if it says
	// the destination is reachable, no exit comparison can change that.
	res := cfg.LocalProber.Probe(ctx, domain, ips)
	persistProbe(ctx, store, res)
	verdict := decision.Classify(res)
	hotReason := reasonFromProbe(res)

	// Phase 2: exit-compare validator. Only runs when local already failed —
	// that's both the only case where remote can change the verdict (it can
	// never veto a local OK; if the gateway can reach it, no need to tunnel),
	// and the bandwidth-cheapest filter for the operator's remote server.
	if useExitCompare && verdict == decision.Hot && cfg.RemoteProber != nil {
		rres := cfg.RemoteProber.Probe(ctx, domain, ips)
		persistProbe(ctx, store, rres)
		switch {
		case rres.TCPOK && rres.TLSOK:
			// Real DPI block: direct path dead, exit confirms target is alive.
			hotReason = "local:" + reasonFromProbe(res) + "|remote:ok"
		case isRemoteTransportFailure(rres):
			// Remote prober itself unreachable / timed out / returned non-200.
			// Treat as "no opinion" — never let an outage of the operator's
			// probe-server cascade into Ignore-ing real DPI blocks. Stick with
			// the local Hot verdict.
			hotReason = "local:" + reasonFromProbe(res) + "|remote:unavailable:" + reasonFromProbe(rres)
		default:
			// Both probers reported a real failure: methodological FP (port
			// wrong, dead server, geofence on both vantage points).
			verdict = decision.Ignore
			hotReason = "local:" + reasonFromProbe(res) + "|remote:" + reasonFromProbe(rres)
		}
	}

	cooldown := time.Now().UTC().Add(cfg.ProbeCooldown)

	switch verdict {
	case decision.Hot:
		if err := store.SetDomainState(ctx, domain, "hot", cooldown); err != nil {
			log.Printf("set state hot %q: %v", domain, err)
		}
		if err := store.UpsertHotEntry(ctx, domain,
			hotReason, time.Now().UTC().Add(cfg.HotTTL)); err != nil {
			log.Printf("upsert hot %q: %v", domain, err)
		}
		log.Printf("probe %s → HOT (%s, %dms)", domain, hotReason, res.LatencyMS)
		// Nudge the ipset syncer — a new IP may now need to be tunneled.
		select {
		case ipsetTrigger <- struct{}{}:
		default:
		}
	case decision.Ignore:
		if err := store.SetDomainState(ctx, domain, "ignore", cooldown); err != nil {
			log.Printf("set state ignore %q: %v", domain, err)
		}
		// If a previous probe (often the inline fast-path) put this domain in
		// hot_entries, drop it now that we've confirmed it's not actually
		// blocked. Without this the FP would sit in ipset for the full HotTTL.
		if removed, err := store.DeleteHotEntry(ctx, domain); err != nil {
			log.Printf("delete hot %q: %v", domain, err)
		} else if removed {
			log.Printf("probe %s → IGNORE (overruled prior hot, %s)", domain, hotReason)
			select {
			case ipsetTrigger <- struct{}{}:
			default:
			}
		}
	default:
		if err := store.SetDomainState(ctx, domain, "watch", cooldown); err != nil {
			log.Printf("set state watch %q: %v", domain, err)
		}
	}
}

// persistProbe writes one probes row. Both local and remote results go through
// here so the probes table keeps a per-backend audit trail without any schema
// change — the FailureReason text already distinguishes them when callers
// prefix it (e.g. "remote:tcp:timeout").
func persistProbe(ctx context.Context, store *storage.Store, res prober.Result) {
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
		log.Printf("persist probe %q: %v", res.Domain, err)
	}
}

func reasonFromProbe(r prober.Result) string {
	if r.FailureReason != "" {
		return r.FailureReason
	}
	return "ok"
}

// isRemoteTransportFailure reports whether a remote prober result represents
// the prober itself being unreachable (network error, timeout, non-200) rather
// than a real verdict from a working remote. RemoteProber.Probe prefixes those
// reasons with "remote:" — see internal/prober/remote.go failedRemote.
func isRemoteTransportFailure(r prober.Result) bool {
	return strings.HasPrefix(r.FailureReason, "remote:")
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
		desired, expanded, err := computeDesiredIPs(ctx, store, cfg)
		if err != nil {
			log.Printf("ipset: compute desired: %v", err)
			return
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
				cfg.IpsetName, added, removed, len(list), expanded)
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

// computeDesiredIPs walks hot ∪ cache and returns the union of IPs that
// should sit in the engine-managed ipset (ladon_engine). Pulled out of
// runIpsetSyncer's inline closure so tests can validate the eTLD+1
// expansion logic without needing root / a real kernel ipset.
//
// Manual-allow lives in a SEPARATE ipset (ladon_manual) populated by
// dnsmasq directly via ipset= directives — it's intentionally absent from
// this function's union so ladon's destructive reconcile never strips an
// IP that dnsmasq added but ladon doesn't know about.
func computeDesiredIPs(ctx context.Context, store *storage.Store, cfg Config) (map[string]struct{}, int, error) {
	now := time.Now().UTC()
	freshSince := now.Add(-cfg.DNSFreshness)

	hots, err := store.ListHotEntries(ctx, now)
	if err != nil {
		return nil, 0, fmt.Errorf("list hot: %w", err)
	}
	cache, err := store.ListCacheEntries(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list cache: %w", err)
	}

	sources := make([]string, 0, len(hots)+len(cache))
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

	// confirmedByETLD counts hot+cache evidence per family. The ≥2 gate keeps
	// expansion conservative — one accidentally-failed probe shouldn't drag a
	// whole CDN's IP space into the tunnel.
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
			return nil, 0, fmt.Errorf("lookup ips %q: %w", d, err)
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
			return nil, 0, fmt.Errorf("lookup etld %q: %w", root, err)
		}
		for _, ip := range siblingIPs {
			desired[ip] = struct{}{}
		}
	}
	return desired, len(expandedETLDs), nil
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
