// Package engine wires all pipeline stages (tail → ingest → probe → decide)
// into a single long-running process.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/belotserkovtsev/ladon/internal/decision"
	"github.com/belotserkovtsev/ladon/internal/dnsmasqcfg"
	"github.com/belotserkovtsev/ladon/internal/dnssrc"
	"github.com/belotserkovtsev/ladon/internal/etld"
	"github.com/belotserkovtsev/ladon/internal/ipset"
	"github.com/belotserkovtsev/ladon/internal/manual"
	"github.com/belotserkovtsev/ladon/internal/obs"
	"github.com/belotserkovtsev/ladon/internal/prober"
	"github.com/belotserkovtsev/ladon/internal/scorer"
	"github.com/belotserkovtsev/ladon/internal/storage"
	"github.com/belotserkovtsev/ladon/internal/watcher"
)

// Component-tagged loggers, rebound to the configured default in Run. They
// default to slog.Default() so package funcs called outside Run (tests) still
// log somewhere instead of panicking on a nil logger.
var (
	logEngine = slog.Default()
	logIngest = slog.Default()
	logProbe  = slog.Default()
	logIpset  = slog.Default()
	logMaint  = slog.Default()
	logReval  = slog.Default()
)

// setMeta best-effort writes a runtime_meta heartbeat, warning (not failing the
// stage) if the write errors — a failed meta write means the DB is unhappy,
// which is worth surfacing but never worth killing the pipeline over.
func setMeta(ctx context.Context, store *storage.Store, key, value string) {
	if err := store.SetMeta(ctx, key, value); err != nil {
		logEngine.Warn("runtime_meta write failed", "key", key, "err", err)
	}
}

func setMetaTime(ctx context.Context, store *storage.Store, key string, t time.Time) {
	setMeta(ctx, store, key, storage.FormatTime(t))
}

// loadDenyExtensions walks cfg.DenyExtensions, reads each preset from
// ExtensionsPath/<name>.txt, and upserts its domains into manual_entries
// with list_name='deny'. Missing files log a warning and skip — same
// forgiving behavior as allow-extensions.
//
// Unlike allow-extensions (which are delegated to dnsmasq via ipset=),
// deny-extensions go through the DB because the engine's ingest-time
// skip and probe-worker filter both query manual_entries directly.
func loadDenyExtensions(ctx context.Context, store *storage.Store, cfg Config) {
	for _, name := range cfg.DenyExtensions {
		path := filepath.Join(cfg.ExtensionsPath, name+".txt")
		if _, err := os.Stat(path); err != nil {
			logEngine.Warn("deny extension file not found", "ext", name, "path", path)
			continue
		}
		n, err := manual.Load(ctx, store, path, "deny")
		if err != nil {
			logEngine.Error("deny extension load failed", "ext", name, "err", err)
			continue
		}
		logEngine.Info("deny extension loaded", "ext", name, "domains", n, "path", path)
	}
}

// collectManualEntries reads the operator's manual-allow file plus every
// enabled extension, returns deduplicated domains and CIDRs. Domains go
// to dnsmasq's `ipset=/domain/<set>` directive; CIDRs go to a separate
// hash:net ipset (see runCIDRSyncer) since dnsmasq has no path for them.
func collectManualEntries(cfg Config) (manual.Entries, error) {
	seenDomain := map[string]struct{}{}
	seenCIDR := map[string]struct{}{}
	var out manual.Entries
	add := func(e manual.Entries) {
		for _, d := range e.Domains {
			if _, ok := seenDomain[d]; ok {
				continue
			}
			seenDomain[d] = struct{}{}
			out.Domains = append(out.Domains, d)
		}
		for _, c := range e.CIDRs {
			if _, ok := seenCIDR[c]; ok {
				continue
			}
			seenCIDR[c] = struct{}{}
			out.CIDRs = append(out.CIDRs, c)
		}
	}

	if cfg.ManualAllowPath != "" {
		e, err := manual.ReadEntries(cfg.ManualAllowPath)
		if err != nil {
			return out, fmt.Errorf("manual-allow %q: %w", cfg.ManualAllowPath, err)
		}
		add(e)
	}
	for _, name := range cfg.AllowExtensions {
		path := filepath.Join(cfg.ExtensionsPath, name+".txt")
		if _, err := os.Stat(path); err != nil {
			logEngine.Warn("allow extension file not found", "ext", name, "path", path)
			continue
		}
		e, err := manual.ReadEntries(path)
		if err != nil {
			logEngine.Error("allow extension read failed", "ext", name, "err", err)
			continue
		}
		logEngine.Info("allow extension loaded", "ext", name, "domains", len(e.Domains), "cidrs", len(e.CIDRs), "path", path)
		add(e)
	}
	return out, nil
}

// Config holds runtime knobs.
type Config struct {
	LogPath                string        // dnsmasq log to follow
	FromStart              bool          // tail from beginning of file
	DNSSource              string        // ingest source: "auto" (by OS) | "dnsmasq" | "unbound"
	UnboundSocket          string        // unix socket the unbound module writes observations to
	ProbeInterval          time.Duration // how often probe worker wakes up
	ProbeBatch             int           // how many candidates per wake
	ProbeTimeout           time.Duration // per-stage probe timeout
	ProbeCooldown          time.Duration // how long before re-probing a domain
	InlineProbeConcurrency int           // max concurrent inline probes (0 disables inline fast-path)
	HotTTL                 time.Duration // lifetime of a hot_entries row
	ExpiryInterval         time.Duration // hot_entries sweep cadence
	MaintenanceInterval    time.Duration // WAL checkpoint + probes/dns_cache prune cadence
	IpsetName              string        // engine-managed ipset name (default ladon_engine)
	ManualIpsetName        string        // dnsmasq-managed ipset name (default ladon_manual)
	CIDRIpsetName          string        // CIDR ipset name for hash:net entries (default ladon_cidr; "" disables)
	IpsetInterval          time.Duration // ipset reconcile cadence (periodic safety sweep)
	DNSFreshness           time.Duration // how recent a dns_cache entry must be to ship IPs to ipset
	FamilyConfirmThreshold int           // ≥N confirmed (hot/cache) members → trust the eTLD+1 family: expand its IPs AND stop probing new members (state=covered)
	Scorer                 scorer.Config // hot → cache promotion settings
	ManualAllowPath        string        // optional path to manual allow list file
	ManualDenyPath         string        // optional path to manual deny list file
	IgnorePeer             string        // peer IP to skip (gateway self, etc.)

	// Version is the running binary's version string, recorded to runtime_meta
	// at startup so `ladon doctor`/`status` can report it. Empty in tests.
	Version string

	// AllowExtensions are bundled allow-list presets (e.g. "ai", "twitch")
	// that ship with ladon and are opt-in by name. Each name resolves to
	// ExtensionsPath/<name>.txt, which is loaded with the same parser as
	// ManualAllowPath. See release/extensions/ for the shipped presets.
	AllowExtensions []string
	ExtensionsPath  string // default "extensions" (relative to WorkingDirectory)

	// DenyExtensions are bundled deny-list presets loaded from the same
	// ExtensionsPath pool. Each name resolves to ExtensionsPath/<name>.txt
	// and is upserted into manual_entries with list_name='deny' — same tier
	// as ManualDenyPath, so tailer skip and probe-worker filter both honor it.
	DenyExtensions []string

	// LocalProber is the always-on baseline. Used by the inline fast-path from
	// the tailer (where remote round-trips would blow the sub-second latency
	// budget) and as the first stage of the batch worker. Defaults to NewLocal.
	LocalProber prober.Prober

	// Publish writes out what ladon currently judges blocked, for tools that
	// enforce differently than the kernel sets do. Off unless a path is given.
	Publish PublishConfig

	// RemoteProber is the optional exit-compare validator. When non-nil, the
	// batch worker runs it ONLY after a local FAIL, and uses the combined
	// verdict: local FAIL + remote OK = real DPI block (Hot); local FAIL +
	// remote FAIL = methodological FP (Ignore — port wrong, dead server,
	// geofence on both vantage points). Inline path never uses this.
	RemoteProber prober.Prober

	// Revalidate controls Phase-7 re-probing of terminal-state domains
	// (cache / ignore). Disabled by default — see RevalidateConfig.
	Revalidate RevalidateConfig

	// ManageDNSMasq lets the engine own dnsmasq's snippet: it writes the
	// manual/extension domains as `ipset=` directives and restarts dnsmasq so
	// they take effect. Default true, and the right choice on a host where
	// ladon and dnsmasq live together, because dnsmasq puts an address in the
	// set while it answers the query — ahead of the client's first packet.
	//
	// Turn it off where ladon cannot (or should not) drive dnsmasq — a
	// container without the host's service manager, or a resolver someone else
	// owns. The engine then fills the manual set itself from what it observes.
	// That path is a hair slower: the address lands once the observation is
	// read rather than during the answer, so a client can race the very first
	// connection to a name it has never resolved before.
	ManageDNSMasq bool
}

// RevalidateConfig tunes Phase-7 revalidation. When Enabled is false the
// revalidator parks and the engine behaves exactly as before. Its job is to
// keep terminal states honest: a 'cache' domain whose block has lifted, and an
// 'ignore' domain that only got blocked later, both stop being permanent — the
// domain is flipped back to 'new' once Streak consecutive probes disagree with
// its state, and normal probing re-classifies it from scratch.
type RevalidateConfig struct {
	Enabled  bool          // master switch (default false → no-op)
	Interval time.Duration // minimum age before a domain is re-checked
	Batch    int           // domains re-probed per worker tick
	Streak   int           // consecutive disagreeing probes before a state flip
}

// PublishConfig controls writing out the current verdict. Ladon programs the
// kernel sets itself, but that primitive is not the only way to act on a
// verdict: a proxy client routes by domain, and an in-place bypass rewrites
// packets without moving them anywhere. Both want the same answer in a form
// they can read, so it is written to a plain file rather than assumed.
//
// Empty Path leaves the stage parked — nothing is written and nothing changes.
type PublishConfig struct {
	Path     string        // where to write; empty disables
	Interval time.Duration // how often to check for changes
}

// Defaults returns a reasonable baseline config.
func Defaults(logPath string) Config {
	return Config{
		LogPath:                logPath,
		DNSSource:              "auto",
		UnboundSocket:          dnssrc.DefaultUnboundSocket(),
		ExtensionsPath:         "extensions",
		ProbeInterval:          2 * time.Second,
		ProbeBatch:             4,
		ProbeTimeout:           800 * time.Millisecond,
		ProbeCooldown:          5 * time.Minute,
		InlineProbeConcurrency: 8,
		HotTTL:                 24 * time.Hour,
		ExpiryInterval:         30 * time.Second,
		MaintenanceInterval:    time.Hour,
		IpsetName:              "ladon_engine",
		ManualIpsetName:        "ladon_manual",
		CIDRIpsetName:          "ladon_cidr",
		IpsetInterval:          30 * time.Second, // fallback safety sweep; Hot events trigger immediate syncs
		DNSFreshness:           6 * time.Hour,
		FamilyConfirmThreshold: 10, // empirically: captures all CDN families (≥50 members) while excluding broad-namespace ones with few confirmed (google.com/azure.com seen at 2)
		Scorer:                 scorer.Defaults(),
		ManualAllowPath:        "",
		ManualDenyPath:         "",
		IgnorePeer:             "10.10.0.1",
		ManageDNSMasq:          true,
		Publish:                PublishConfig{Interval: time.Minute},
		Revalidate: RevalidateConfig{
			Enabled:  false,
			Interval: 6 * time.Hour,
			Batch:    4,
			Streak:   3,
		},
	}
}

// Run starts all pipeline stages and blocks until ctx is cancelled.
func Run(ctx context.Context, store *storage.Store, cfg Config) error {
	// Bind component loggers off whatever default the CLI configured.
	logEngine = obs.Logger("engine")
	logIngest = obs.Logger("ingest")
	logProbe = obs.Logger("prober")
	logIpset = obs.Logger("ipset")
	logMaint = obs.Logger("maintenance")
	logReval = obs.Logger("revalidate")

	// Record identity/liveness up front so a `ladon doctor` run right after
	// startup already sees the process.
	setMetaTime(ctx, store, "started_at", time.Now().UTC())
	setMeta(ctx, store, "version", cfg.Version)
	setMeta(ctx, store, "pid", strconv.Itoa(os.Getpid()))

	if cfg.LocalProber == nil {
		cfg.LocalProber = prober.NewLocal(cfg.ProbeTimeout)
	}
	if cfg.RemoteProber != nil {
		logEngine.Info("probe backends configured",
			"baseline", cfg.LocalProber.Name(), "exit_compare", cfg.RemoteProber.Name())
	} else {
		logEngine.Info("probe backend configured", "baseline", cfg.LocalProber.Name())
	}
	// Manual-deny still goes through the database — engine consults
	// IsInDenyList during ingest to skip those domains entirely.
	if n, err := manual.Load(ctx, store, cfg.ManualDenyPath, "deny"); err != nil {
		logEngine.Error("manual deny load failed", "err", err)
	} else if n > 0 {
		logEngine.Info("manual deny loaded", "entries", n, "path", cfg.ManualDenyPath)
	}
	loadDenyExtensions(ctx, store, cfg)

	// Manual-allow + extensions: on the dnsmasq (Linux) path they're delegated to
	// dnsmasq's native ipset= directive below; on the unbound path the engine's
	// manual-syncer fills ladon_manual instead (launched further down). dnsmasq is
	// preferred where available because:
	//   1. dnsmasq adds resolved IPs to the kernel set BEFORE returning the
	//      DNS answer, so the client's first TCP SYN already finds the IP.
	//      Our tail-and-reconcile loop can never win that race.
	//   2. dnsmasq walks CNAME chains internally — no need for ladon-side
	//      query-id tracking or eTLD+1 expansion to compensate.
	//   3. Manual list = operator's stated intent; doesn't need probe-driven
	//      verification. Letting dnsmasq own it keeps that mental model clean.
	manualEntries, err := collectManualEntries(cfg)
	if err != nil {
		logEngine.Error("collect manual entries failed", "err", err)
	}
	// Who fills the manual set: dnsmasq via its own `ipset=` directive, or the
	// engine from what it observes. Delegating needs both a dnsmasq to talk to
	// and permission to drive it; otherwise the engine takes the job itself
	// (the manual-syncer launched further down).
	delegateManual := cfg.ManageDNSMasq && dnssrc.Resolve(cfg.DNSSource) == "dnsmasq"
	if cfg.ManualIpsetName != "" && delegateManual {
		changed, err := dnsmasqcfg.Write(cfg.ManualIpsetName, manualEntries.Domains)
		switch {
		case err != nil:
			logEngine.Error("dnsmasq config write failed", "err", err)
		case changed:
			logEngine.Info("manual list written to dnsmasq",
				"domains", len(manualEntries.Domains), "path", dnsmasqcfg.Path, "ipset", cfg.ManualIpsetName)
			if err := dnsmasqcfg.Restart(ctx); err != nil {
				logEngine.Warn("dnsmasq restart failed — manual list activates on next dnsmasq restart", "err", err)
			}
		default:
			logEngine.Debug("manual list unchanged — dnsmasq restart skipped",
				"domains", len(manualEntries.Domains), "path", dnsmasqcfg.Path)
		}
	}
	// CIDR entries skip dnsmasq entirely — they aren't DNS-driven. Reconcile
	// the hash:net ipset directly so any line operator removed from a file
	// also leaves the kernel set on next ladon start.
	syncCIDRSet(ctx, cfg, manualEntries.CIDRs)

	// Inline probe semaphore caps concurrent fast-path probes from the tailer.
	// Regular probe-worker remains for re-probes and semaphore-full fallback.
	sem := make(chan struct{}, max(1, cfg.InlineProbeConcurrency))

	// Buffered 1 so hot-probe senders never block. Drain-and-sync is idempotent;
	// a single buffered slot coalesces storms of hot events into one sync pass.
	ipsetTrigger := make(chan struct{}, 1)

	// Same shape for the manual set, used only when the engine fills it itself.
	// Ingest pokes this the moment it sees a manual-list name resolve, so the
	// address is in the set on the heels of the answer instead of waiting out
	// the safety tick.
	manualTrigger := make(chan struct{}, 1)
	var manualNames *nameSet
	if !delegateManual {
		manualNames = newNameSet(manualEntries.Domains)
	}

	errCh := make(chan error, 9) // 8 always-on stages + manual-syncer when the engine owns the manual set

	// launch runs a pipeline stage and reports to errCh only if it returns
	// BEFORE shutdown was requested. A stage exiting early (a tailer log-read
	// error, a probe-worker DB failure, …) is abnormal: report it so Run returns
	// non-nil, the process exits, and systemd's Restart= fires — instead of the
	// daemon sitting "active" with a dead stage and stale ipsets.
	launch := func(name string, fn func() error) {
		go func() {
			err := fn()
			if ctx.Err() != nil {
				return // graceful shutdown — stage unwinding on ctx, not a failure
			}
			if err == nil {
				err = errors.New("exited unexpectedly")
			}
			errCh <- fmt.Errorf("%s: %w", name, err)
		}()
	}

	ingestSrc := dnssrc.New(dnssrc.Config{Kind: cfg.DNSSource, LogPath: cfg.LogPath, StartAtEnd: !cfg.FromStart, UnboundSocket: cfg.UnboundSocket})
	launch("ingest", func() error {
		return runIngest(ctx, store, cfg, sem, ipsetTrigger, ingestSrc, manualNames, manualTrigger)
	})
	launch("probe-worker", func() error { return runProbeWorker(ctx, store, cfg, ipsetTrigger) })
	launch("expiry-sweeper", func() error { return runExpirySweeper(ctx, store, cfg) })
	launch("ipset-syncer", func() error { return runIpsetSyncer(ctx, store, cfg, ipsetTrigger) })
	// When the manual set isn't delegated to dnsmasq, the engine reconciles it
	// from the observed IPs of the manual-allow + extension domains. Gated on
	// the same flag as the snippet above so the two never fight over the set.
	if cfg.ManualIpsetName != "" && len(manualEntries.Domains) > 0 && !delegateManual {
		launch("manual-syncer", func() error {
			return runManualSyncer(ctx, store, cfg, manualEntries.Domains, manualTrigger)
		})
	}
	launch("maintenance", func() error { return runMaintenance(ctx, store, cfg) })
	launch("scorer", func() error { return scorer.Run(ctx, store, cfg.Scorer) })
	launch("publisher", func() error { return runVerdictPublisher(ctx, store, cfg) })
	launch("revalidator", func() error { return runRevalidator(ctx, store, cfg, ipsetTrigger) })

	select {
	case <-ctx.Done():
		return nil // graceful shutdown (SIGTERM) — clean exit
	case err := <-errCh:
		return err // a stage died mid-run — fail fast so systemd restarts us
	}
}

// nameSet answers "is this name on the manual list", counting a subdomain of a
// listed name as a member — the manual set is filled by eTLD+1 expansion too,
// so a hit on any member of the family is worth a sync.
type nameSet struct {
	exact map[string]struct{}
	roots map[string]struct{}
}

func newNameSet(domains []string) *nameSet {
	s := &nameSet{exact: map[string]struct{}{}, roots: map[string]struct{}{}}
	for _, d := range domains {
		s.exact[d] = struct{}{}
		if r := etld.Compute(d); r != "" {
			s.roots[r] = struct{}{}
		}
	}
	return s
}

func (s *nameSet) matches(domain string) bool {
	if s == nil {
		return false
	}
	if _, ok := s.exact[domain]; ok {
		return true
	}
	if r := etld.Compute(domain); r != "" {
		_, ok := s.roots[r]
		return ok
	}
	return false
}

func runIngest(ctx context.Context, store *storage.Store, cfg Config, sem chan struct{}, ipsetTrigger chan<- struct{}, src dnssrc.Source, manualNames *nameSet, manualTrigger chan<- struct{}) error {
	events, errs := src.Events(ctx)
	ingested, skipped := 0, 0
	report := time.NewTicker(30 * time.Second)
	defer report.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err, ok := <-errs:
			if ok && err != nil {
				return fmt.Errorf("ingest: %w", err)
			}
		case obs, ok := <-events:
			if !ok {
				return nil
			}
			// Every Observation is a resolved query: domain + the v4 IPs the
			// client got, CNAME already re-attributed by the source. The engine
			// stays resolver-agnostic and never resolves anything itself.
			if obs.Client == "" || obs.Client == cfg.IgnorePeer {
				skipped++
				continue
			}
			if deny, _ := store.IsInDenyList(ctx, obs.Domain, etld.Compute(obs.Domain)); deny {
				skipped++
				continue
			}
			if _, err := watcher.Ingest(ctx, store, watcher.Event{
				Domain: obs.Domain,
				Peer:   obs.Client,
			}); err != nil {
				logIngest.Error("ingest failed", "domain", obs.Domain, "err", err)
				continue
			}
			// Feed dns_cache (the source of truth for ipset routing, eTLD/family
			// expansion and batch re-probe). Observation IPs are already v4.
			for _, ip := range obs.IPs {
				if err := store.UpsertDNSObservation(ctx, obs.Domain, ip, time.Time{}); err != nil {
					logIngest.Error("dns_cache upsert failed", "domain", obs.Domain, "ip", ip, "err", err)
				}
			}
			ingested++
			// A manual-list name just resolved: nudge the syncer so its address
			// reaches the set now rather than on the next safety tick. Buffered
			// 1, so a burst of names collapses into a single pass.
			if manualNames.matches(obs.Domain) {
				select {
				case manualTrigger <- struct{}{}:
				default:
				}
			}
			// Inline probe fast-path: kick off right after ingest so a freshly
			// observed blocked domain lands in the ipset within sub-second, using
			// the IPs the client actually resolved — no cache race, no self-resolve.
			// probeDomain short-circuits to 'covered' for members of an
			// already-confirmed family, so no probe fires for established CDN churn.
			tryInlineProbe(ctx, store, cfg, obs.Domain, obs.IPs, sem, ipsetTrigger)
		case <-report.C:
			logIngest.Info("ingest progress", "ingested", ingested, "skipped", skipped)
		}
	}
}

// tryInlineProbe kicks an immediate probe in a goroutine when the semaphore
// has room. If the semaphore is full we simply drop the fast-path attempt —
// the regular probe-worker ticks will pick the domain up shortly after, so
// nothing is lost, we just don't beat the worker to it under heavy load.
func tryInlineProbe(ctx context.Context, store *storage.Store, cfg Config, domain string, ips []string, sem chan struct{}, ipsetTrigger chan<- struct{}) {
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
		// Inline path: local-only, probing the IPs the client just resolved. The
		// exit-compare validator (if configured) runs on the batch worker's
		// cooldown re-probe — it would blow the inline latency budget here.
		probeDomain(ctx, store, cfg, domain, ips, ipsetTrigger, false)
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
				logProbe.Error("probe tick failed", "err", err)
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
	freshSince := now.Add(-cfg.DNSFreshness)
	for _, d := range candidates {
		if err := ctx.Err(); err != nil {
			return nil
		}
		// Probe the IPs the client actually resolved (dns_cache). If the fresh
		// window has aged out, fall back to the last-known IPs rather than
		// self-resolving — on a gateway a self-resolve would re-enter the very
		// resolver we observe. Candidates only ever reach the table from a
		// resolved observation, so this is virtually always populated.
		ips, err := store.LookupIPs(ctx, d.Domain, freshSince)
		if err != nil {
			logEngine.Warn("dns_cache lookup failed", "domain", d.Domain, "err", err)
		}
		if len(ips) == 0 {
			ips, _ = store.LookupAllIPs(ctx, d.Domain)
		}
		// Batch worker uses exit-compare when RemoteProber is configured —
		// gives the operator's vantage point a vote on borderline calls.
		probeDomain(ctx, store, cfg, d.Domain, ips, ipsetTrigger, true)
	}
	return nil
}

// probeDomain runs one probe→decision→persist cycle for a domain against the
// caller-supplied IPs (the inline path passes what the client just resolved;
// the batch worker passes dns_cache). The engine never resolves DNS itself.
func probeDomain(ctx context.Context, store *storage.Store, cfg Config, domain string, ips []string, ipsetTrigger chan<- struct{}, useExitCompare bool) {
	if err := prober.Validate(domain); err != nil {
		_ = store.SetDomainState(ctx, domain, "ignore", time.Time{})
		return
	}
	// Single chokepoint for BOTH probe paths (inline + batch worker): if this
	// domain's eTLD+1 family is already confirmed blocked, don't probe it. Mark
	// it 'covered' (excluded from both candidate queries) and nudge the syncer —
	// its IP is routed via the family's eTLD+1 expansion. Stops re-probing every
	// rotating CDN subdomain once the family is established.
	if confirmed, _ := store.FamilyConfirmed(ctx, etld.Compute(domain), cfg.FamilyConfirmThreshold); confirmed {
		if _, err := store.MarkCovered(ctx, domain); err != nil {
			logEngine.Error("mark covered failed", "domain", domain, "err", err)
		}
		select {
		case ipsetTrigger <- struct{}{}:
		default:
		}
		return
	}
	// Phase 1: local probe (always). This is the gateway-side view; if it says
	// the destination is reachable, no exit comparison can change that.
	res := cfg.LocalProber.Probe(ctx, domain, ips)
	localID := persistProbe(ctx, store, res)
	verdict := decision.Classify(res)
	hotReason := reasonFromProbe(res)

	// Phase 2: exit-compare validator. Only runs when local already failed —
	// that's both the only case where remote can change the verdict (it can
	// never veto a local OK; if the gateway can reach it, no need to tunnel),
	// and the bandwidth-cheapest filter for the operator's remote server.
	//
	// Combine logic is code-aware: ClassifyRemote distinguishes full-chain OK
	// from TCP+TLS-only-OK (legacy remote) from HTTP-stage-fail. The latter
	// matters for HTTP-class ambiguous local codes (http_cutoff/timeout/error)
	// where server-side severing — not DPI — is the cause; pre-PR combine
	// looked only at TCP+TLS and false-promoted Yandex-class endpoints to Blocked.
	if useExitCompare && verdict == decision.Blocked && cfg.RemoteProber != nil {
		rres := cfg.RemoteProber.Probe(ctx, domain, ips)
		persistProbe(ctx, store, rres)
		newVerdict, tag := decision.CombineExitCompare(res.FailureCode, decision.ClassifyRemote(rres))
		verdict = newVerdict
		hotReason = "local:" + reasonFromProbe(res) + "|" + tag + ":" + reasonFromProbe(rres)
	}

	// Stamp the authoritative cycle verdict on the local anchor row. Only the
	// batch path (useExitCompare) is authoritative; the inline fast-path leaves
	// verdict NULL — provisional, not counted by the scorer toward promotion.
	if useExitCompare && localID != 0 {
		if err := store.SetProbeVerdict(ctx, localID, string(verdict)); err != nil {
			logProbe.Error("set probe verdict failed", "domain", domain, "err", err)
		}
	}

	cooldown := time.Now().UTC().Add(cfg.ProbeCooldown)

	switch verdict {
	case decision.Blocked:
		if err := store.SetDomainState(ctx, domain, "hot", cooldown); err != nil {
			logProbe.Error("set state hot failed", "domain", domain, "err", err)
		}
		if err := store.UpsertHotEntry(ctx, domain,
			hotReason, time.Now().UTC().Add(cfg.HotTTL)); err != nil {
			logProbe.Error("upsert hot failed", "domain", domain, "err", err)
		}
		logProbe.Info("probe blocked → hot",
			"domain", domain, "reason", hotReason,
			"failure_code", string(res.FailureCode), "latency_ms", res.LatencyMS)
		// Nudge the ipset syncer — a new IP may now need to be tunneled.
		select {
		case ipsetTrigger <- struct{}{}:
		default:
		}
	case decision.Clear:
		if err := store.SetDomainState(ctx, domain, "ignore", cooldown); err != nil {
			logProbe.Error("set state ignore failed", "domain", domain, "err", err)
		}
		// If a previous probe (often the inline fast-path) put this domain in
		// hot_entries, drop it now that we've confirmed it's not actually
		// blocked. Without this the FP would sit in ipset for the full HotTTL.
		if removed, err := store.DeleteHotEntry(ctx, domain); err != nil {
			logProbe.Error("delete hot failed", "domain", domain, "err", err)
		} else if removed {
			logProbe.Info("probe clear → ignore (overruled prior hot)", "domain", domain, "reason", hotReason)
			select {
			case ipsetTrigger <- struct{}{}:
			default:
			}
		}
	default:
		// Classify and CombineExitCompare only ever yield Blocked or Clear; this
		// guards against a future verdict slipping through unhandled rather than
		// silently mis-stating the domain's state.
		logProbe.Warn("unhandled verdict, leaving state unchanged", "domain", domain, "verdict", string(verdict))
	}
}

// runRevalidator re-probes terminal-state domains (cache / ignore) on a slow
// cadence and flips one back to 'new' once cfg.Revalidate.Streak consecutive
// probes disagree with its state — a lifted block stops being tunneled forever,
// and a domain blocked only later stops sitting in 'ignore' forever. Normal
// probing then re-classifies the reset domain from scratch. Disabled by default:
// when off it parks on ctx and never touches state, so it can neither crash the
// daemon nor change behavior.
func runRevalidator(ctx context.Context, store *storage.Store, cfg Config, ipsetTrigger chan<- struct{}) error {
	rc := cfg.Revalidate
	if !rc.Enabled {
		<-ctx.Done()
		return nil
	}
	if rc.Interval <= 0 {
		rc.Interval = 6 * time.Hour
	}
	if rc.Batch <= 0 {
		rc.Batch = 4
	}
	if rc.Streak <= 0 {
		rc.Streak = 3
	}
	logReval.Info("revalidator enabled",
		"interval", rc.Interval.String(), "batch", rc.Batch, "streak", rc.Streak)

	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			now := time.Now().UTC()
			cands, err := store.ListRevalidationCandidates(ctx, rc.Batch, now.Add(-rc.Interval))
			if err != nil {
				logReval.Error("list candidates failed", "err", err)
				continue
			}
			for _, d := range cands {
				ips, err := store.LookupAllIPs(ctx, d.Domain)
				if err != nil || len(ips) == 0 {
					// No observed IPs to probe — stamp reval_at (treated as
					// "agrees": resets streak, keeps state) so we don't hot-loop.
					if _, _, aerr := store.ApplyRevalidation(ctx, d.Domain, false, rc.Streak, now); aerr != nil {
						logReval.Error("stamp failed", "domain", d.Domain, "err", aerr)
					}
					continue
				}
				res := cfg.LocalProber.Probe(ctx, d.Domain, ips)
				persistProbe(ctx, store, res)
				verdict := decision.Classify(res)
				disagrees := (d.State == "cache" && verdict == decision.Clear) ||
					(d.State == "ignore" && verdict == decision.Blocked)
				action, streak, err := store.ApplyRevalidation(ctx, d.Domain, disagrees, rc.Streak, now)
				if err != nil {
					logReval.Error("apply failed", "domain", d.Domain, "err", err)
					continue
				}
				switch action {
				case "reset":
					logReval.Info("flipped terminal domain to new",
						"domain", d.Domain, "from", d.State, "verdict", verdict)
					select {
					case ipsetTrigger <- struct{}{}:
					default:
					}
				case "pending":
					logReval.Debug("revalidation disagreement",
						"domain", d.Domain, "state", d.State, "verdict", verdict, "streak", streak)
				}
			}
		}
	}
}

// persistProbe writes one probes row and returns its id. Both local and remote
// results go through here so the probes table keeps a per-backend audit trail —
// the FailureReason text distinguishes them when callers prefix it (e.g.
// "remote:tcp:timeout"). Returns 0 on error.
func persistProbe(ctx context.Context, store *storage.Store, res prober.Result) int64 {
	dns, tcp, tls := res.DNSOK, res.TCPOK, res.TLSOK
	id, err := store.InsertProbe(ctx, storage.ProbeResult{
		Domain:        res.Domain,
		DNSOK:         &dns,
		TCPOK:         &tcp,
		TLSOK:         &tls,
		HTTPOK:        res.HTTPOK,
		FailureReason: res.FailureReason,
	}, time.Time{})
	if err != nil {
		logEngine.Error("persist probe failed", "domain", res.Domain, "err", err)
		return 0
	}
	return id
}

func reasonFromProbe(r prober.Result) string {
	if r.FailureReason != "" {
		return r.FailureReason
	}
	return "ok"
}

// syncCIDRSet reconciles the hash:net ipset (default ladon_cidr) against the
// CIDR list collected from manual-allow + extensions. One-shot at start, no
// periodic sweep: extension files are read once at startup, so there's no
// drift source — a SIGHUP/restart picks up edits the same way the dnsmasq
// snippet does. Missing set is logged and skipped, same as the engine syncer.
func syncCIDRSet(ctx context.Context, cfg Config, cidrs []string) {
	if cfg.CIDRIpsetName == "" {
		return
	}
	mgr := ipset.New(cfg.CIDRIpsetName)
	ok, err := mgr.Exists(ctx)
	if err != nil {
		logIpset.Error("cidr ipset exists check failed", "set", cfg.CIDRIpsetName, "err", err)
		return
	}
	if !ok {
		if len(cidrs) > 0 {
			logIpset.Warn("cidr ipset not found — skipping CIDR sync",
				"set", cfg.CIDRIpsetName,
				"hint", fmt.Sprintf("ipset create %s hash:net family inet", cfg.CIDRIpsetName))
		}
		return
	}
	added, removed, err := mgr.Reconcile(ctx, cidrs)
	if err != nil {
		logIpset.Error("cidr ipset reconcile failed", "set", cfg.CIDRIpsetName, "err", err)
		return
	}
	logIpset.Info("cidr ipset synced", "set", cfg.CIDRIpsetName, "added", added, "removed", removed, "total", len(cidrs))
}

// runIpsetSyncer keeps the gateway-side ipset (e.g. "prod") in sync with
// hot_entries ∪ cache_entries ∪ manual-allow. Triggered both by a periodic
// safety ticker and by the ipsetTrigger channel — hot probes signal the
// channel so a just-observed blocked IP lands in `prod` within ~milliseconds.
func runIpsetSyncer(ctx context.Context, store *storage.Store, cfg Config, trigger <-chan struct{}) error {
	// Every "cannot do this" path below waits on ctx rather than returning.
	// A launched stage that returns early is reported as a failure, the daemon
	// exits and the service manager restarts it — which fixes nothing here,
	// because an absent set or an absent `ipset` is a host problem that no
	// number of restarts resolves. What the restarts do accomplish is bouncing
	// dnsmasq every few seconds and flapping DNS for everyone behind us.
	//
	// So the daemon stays up and keeps doing the rest of its job: observing,
	// probing, publishing. It just isn't programming the set, which is stated
	// loudly here and reported by `ladon doctor`.
	if cfg.IpsetName == "" {
		<-ctx.Done()
		return nil
	}
	mgr := ipset.New(cfg.IpsetName)

	ok, err := mgr.Exists(ctx)
	if err != nil {
		logIpset.Error("cannot use the set — routing is NOT being programmed",
			"set", cfg.IpsetName, "err", err)
		<-ctx.Done()
		return nil
	}
	if !ok {
		logIpset.Error("set not found — routing is NOT being programmed",
			"set", cfg.IpsetName,
			"hint", fmt.Sprintf("ipset create %s hash:ip family inet -exist", cfg.IpsetName))
		<-ctx.Done()
		return nil
	}

	ticker := time.NewTicker(cfg.IpsetInterval)
	defer ticker.Stop()

	syncNow := func() {
		desired, expanded, err := computeDesiredIPs(ctx, store, cfg)
		if err != nil {
			logIpset.Error("compute desired ips failed", "err", err)
			return
		}
		list := make([]string, 0, len(desired))
		for ip := range desired {
			list = append(list, ip)
		}
		added, removed, err := mgr.Reconcile(ctx, list)
		if err != nil {
			logIpset.Error("ipset reconcile failed", "set", cfg.IpsetName, "err", err)
			return
		}
		if added > 0 || removed > 0 {
			logIpset.Info("ipset synced",
				"set", cfg.IpsetName, "added", added, "removed", removed,
				"total", len(list), "etlds_expanded", expanded)
		}
		// Record the reconcile outcome for doctor/status — these facts (last
		// reconcile time, the set size we last pushed) aren't recoverable from
		// any other table.
		now := time.Now().UTC()
		setMetaTime(ctx, store, "last_reconcile_at", now)
		setMeta(ctx, store, "ipset_engine_size", strconv.Itoa(len(list)))
		setMeta(ctx, store, "reconcile_added", strconv.Itoa(added))
		setMeta(ctx, store, "reconcile_removed", strconv.Itoa(removed))
		setMeta(ctx, store, "ipset_etlds_expanded", strconv.Itoa(expanded))
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

// runManualSyncer fills the ladon_manual SET from the observed IPs of the
// manual-allow + non-CIDR extension domains. It's the unbound/pfctl analog of
// dnsmasq's ipset= directive: on Linux dnsmasq owns ladon_manual, but on the
// unbound path nothing else fills it, so the GUI's "always tunneled" promise
// would be empty without this. Gated to the non-dnsmasq path by the caller, so
// its destructive Reconcile never strips IPs dnsmasq added on Linux.
//
// Per domain it unions the exact-name IPs (store.LookupIPs) with the eTLD+1
// family IPs (store.LookupIPsByETLD), mirroring dnsmasq's suffix match — a
// freshly-added manual domain won't tunnel until it has been observed at least
// once (no DNS observation, no IP to push).
func runManualSyncer(ctx context.Context, store *storage.Store, cfg Config, domains []string, trigger <-chan struct{}) error {
	// A launched stage that returns before shutdown is treated as a failure
	// ("exited unexpectedly"), so every "nothing to do" path here waits for ctx
	// rather than returning — manual-allow is optional and must never crash the
	// daemon.
	if cfg.ManualIpsetName == "" || len(domains) == 0 {
		<-ctx.Done()
		return nil
	}
	mgr := ipset.New(cfg.ManualIpsetName)
	ok, err := mgr.Exists(ctx)
	if err != nil {
		logIpset.Error("manual ipset exists check failed", "set", cfg.ManualIpsetName, "err", err)
		<-ctx.Done()
		return nil
	}
	if !ok {
		logIpset.Warn("manual ipset not found — manual-allow not enforced",
			"set", cfg.ManualIpsetName,
			"hint", fmt.Sprintf("ipset create %s hash:ip", cfg.ManualIpsetName))
		<-ctx.Done()
		return nil
	}

	// Family roots are fixed (the manual list is read once at startup).
	roots := map[string]struct{}{}
	for _, d := range domains {
		if r := etld.Compute(d); r != "" {
			roots[r] = struct{}{}
		}
	}

	ticker := time.NewTicker(cfg.IpsetInterval)
	defer ticker.Stop()

	syncNow := func() {
		freshSince := time.Now().UTC().Add(-cfg.DNSFreshness)
		seen := map[string]struct{}{}
		want := make([]string, 0, len(domains))
		add := func(ips []string) {
			for _, ip := range ips {
				if _, dup := seen[ip]; dup {
					continue
				}
				seen[ip] = struct{}{}
				want = append(want, ip)
			}
		}
		for _, d := range domains {
			ips, err := store.LookupIPs(ctx, d, freshSince)
			if err != nil {
				logIpset.Error("manual lookup ips failed", "domain", d, "err", err)
				return
			}
			add(ips)
		}
		for r := range roots {
			ips, err := store.LookupIPsByETLD(ctx, r, freshSince)
			if err != nil {
				logIpset.Error("manual lookup etld failed", "etld", r, "err", err)
				return
			}
			add(ips)
		}
		added, removed, err := mgr.Reconcile(ctx, want)
		if err != nil {
			logIpset.Error("manual ipset reconcile failed", "set", cfg.ManualIpsetName, "err", err)
			return
		}
		if added > 0 || removed > 0 {
			logIpset.Info("manual ipset synced",
				"set", cfg.ManualIpsetName, "added", added, "removed", removed, "total", len(want))
		}
	}
	syncNow()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-trigger:
			syncNow()
		case <-ticker.C:
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

	// confirmedByETLD counts confirmed-blocked members per family. The
	// FamilyConfirmThreshold gate keeps expansion conservative: a broad-namespace
	// family (google.com, azure.com) with only a couple of confirmed members must
	// NOT drag its whole IP space into the tunnel — only families with many
	// confirmed members (real CDNs: fbcdn, googlevideo, akamai clusters) expand.
	// hot_entries and cache_entries are disjoint (PromoteCache drops the hot row
	// on promotion), so a single domain is counted exactly once below.
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
		if root == "" || confirmedByETLD[root] < cfg.FamilyConfirmThreshold {
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
			// Doubles as the engine's liveness heartbeat: a steady tick on a
			// short cadence is exactly what `ladon doctor` checks for staleness.
			setMetaTime(ctx, store, "last_tick_at", time.Now().UTC())
			n, err := store.ExpireHotEntries(ctx, time.Now().UTC())
			if err != nil {
				logEngine.Error("expire hot failed", "err", err)
				continue
			}
			if n > 0 {
				logEngine.Info("expired hot entries", "count", n)
			}
		}
	}
}

// runMaintenance bounds on-disk growth on a slow cadence. Nothing here affects
// correctness — it only reclaims space the rest of the engine never reads again:
//   - WAL checkpoint(TRUNCATE): the long-lived read pool blocks SQLite's passive
//     auto-truncate, so the -wal file grows without this.
//   - prune probes older than the scorer's window (the scorer only ever counts
//     verdicts within Scorer.Window, so older rows are dead weight).
//   - prune dns_cache observations past their freshness horizon (reads already
//     filter on DNSFreshness, so stale rows are never shipped to the ipset).
//
// Retentions carry generous margins so a clock skew or a wider window never
// deletes a row a reader still wants.
// runVerdictPublisher keeps a file in step with what ladon judges blocked, so
// tools that enforce differently than the kernel sets can act on the same
// answer: a proxy client routing by domain, an in-place bypass rewriting
// packets where they are. Ladon decides either way and does not care which.
//
// Rewritten only when the contents actually change, and atomically, so a reader
// polling the file never catches it half-written and never re-reads an
// identical one. Parked when no path is configured.
func runVerdictPublisher(ctx context.Context, store *storage.Store, cfg Config) error {
	// A stage that returns before shutdown is treated as a failure, so the
	// disabled path waits on ctx instead: publishing is optional and must never
	// bring the daemon down with it.
	if cfg.Publish.Path == "" {
		<-ctx.Done()
		return nil
	}
	every := cfg.Publish.Interval
	if every <= 0 {
		every = time.Minute
	}

	var last string
	writeOnce := func() {
		domains, err := store.ListBlockedDomains(ctx)
		if err != nil {
			logEngine.Error("publish: list failed", "err", err)
			return
		}
		var sb strings.Builder
		sb.WriteString("# Domains ladon currently judges blocked. Generated — do not edit.\n")
		sb.WriteString("# One per line, sorted. Subdomains are listed in their own right.\n")
		for _, d := range domains {
			sb.WriteString(d)
			sb.WriteByte('\n')
		}
		body := sb.String()
		if body == last {
			return
		}
		dir := filepath.Dir(cfg.Publish.Path)
		tmp, err := os.CreateTemp(dir, ".ladon-blocked.*")
		if err != nil {
			logEngine.Error("publish: temp file failed", "dir", dir, "err", err)
			return
		}
		tmpPath := tmp.Name()
		defer os.Remove(tmpPath)
		if _, err := tmp.WriteString(body); err != nil {
			tmp.Close()
			logEngine.Error("publish: write failed", "err", err)
			return
		}
		if err := tmp.Chmod(0o644); err != nil {
			tmp.Close()
			logEngine.Error("publish: chmod failed", "err", err)
			return
		}
		if err := tmp.Close(); err != nil {
			logEngine.Error("publish: close failed", "err", err)
			return
		}
		if err := os.Rename(tmpPath, cfg.Publish.Path); err != nil {
			logEngine.Error("publish: rename failed", "path", cfg.Publish.Path, "err", err)
			return
		}
		last = body
		logEngine.Info("published blocked domains", "count", len(domains), "path", cfg.Publish.Path)
	}

	logEngine.Info("publisher enabled", "path", cfg.Publish.Path, "interval", every.String())
	writeOnce()

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			writeOnce()
		}
	}
}

func runMaintenance(ctx context.Context, store *storage.Store, cfg Config) error {
	interval := cfg.MaintenanceInterval
	if interval <= 0 {
		interval = time.Hour
	}
	probeRetention := 2 * cfg.Scorer.Window
	if probeRetention <= 0 {
		probeRetention = 48 * time.Hour
	}
	dnsRetention := cfg.DNSFreshness
	if dnsRetention < 7*24*time.Hour {
		dnsRetention = 7 * 24 * time.Hour
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			now := time.Now().UTC()
			if err := store.Checkpoint(ctx); err != nil {
				logMaint.Error("wal checkpoint failed", "err", err)
			}
			if n, err := store.PruneProbes(ctx, now.Add(-probeRetention)); err != nil {
				logMaint.Error("prune probes failed", "err", err)
			} else if n > 0 {
				logMaint.Info("pruned probes", "count", n, "older_than", probeRetention.String())
			}
			if n, err := store.PruneDNSCache(ctx, now.Add(-dnsRetention)); err != nil {
				logMaint.Error("prune dns_cache failed", "err", err)
			} else if n > 0 {
				logMaint.Info("pruned dns_cache", "count", n, "older_than", dnsRetention.String())
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
