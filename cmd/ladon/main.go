// ladon CLI.
//
// Subcommands:
//
//	init-db                 create/update the SQLite schema
//	probe <domain>          run a DNS/TCP/TLS probe and persist the result
//	observe <d>             record a synthetic DNS observation (for dev)
//	list [N]                show the N most recent domains (default 20)
//	tail [-from-start] P    follow a dnsmasq log file and ingest 'forwarded' events
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/belotserkovtsev/ladon/internal/config"
	"github.com/belotserkovtsev/ladon/internal/dnsmasq"
	"github.com/belotserkovtsev/ladon/internal/engine"
	"github.com/belotserkovtsev/ladon/internal/prober"
	"github.com/belotserkovtsev/ladon/internal/storage"
	"github.com/belotserkovtsev/ladon/internal/tail"
	"github.com/belotserkovtsev/ladon/internal/watcher"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: ladon [-db PATH] [-config PATH] <cmd> [args]
commands:
  init-db
  probe <domain>
  observe <domain> [peer]
  list [N]
  hot
  prune  [-cache] [-hot] [-probes] [-before <ISO date>] [-dry-run]
  tail [-from-start] <logfile>
  run  [-from-start] [-config PATH] <logfile>`)
}

func main() {
	dbPath := flag.String("db", filepath.Join("state", "ladon.db"), "path to SQLite database")
	configPath := flag.String("config", "", "path to YAML config file (optional — defaults apply if empty)")
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := storage.Open(*dbPath)
	if err != nil {
		fatal("open db: %v", err)
	}
	defer store.Close()

	switch args[0] {
	case "init-db":
		if err := store.Init(ctx); err != nil {
			fatal("init: %v", err)
		}
		fmt.Println("initialized:", *dbPath)

	case "probe":
		if len(args) < 2 {
			fatal("probe: missing domain")
		}
		domain := args[1]
		if err := prober.Validate(domain); err != nil {
			fatal("%v", err)
		}
		if err := store.UpsertDomain(ctx, domain, "", time.Time{}); err != nil {
			fatal("upsert: %v", err)
		}
		res := prober.Probe(ctx, domain, 0)
		if _, err := store.InsertProbe(ctx, toStorageResult(res), time.Time{}); err != nil {
			fatal("persist probe: %v", err)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)

	case "observe":
		if len(args) < 2 {
			fatal("observe: missing domain")
		}
		peer := ""
		if len(args) >= 3 {
			peer = args[2]
		}
		obs, err := watcher.Ingest(ctx, store, watcher.Event{Domain: args[1], Peer: peer})
		if err != nil {
			fatal("observe: %v", err)
		}
		if obs == nil {
			fmt.Println("(empty domain — skipped)")
		} else {
			fmt.Printf("observed %s (peer=%s)\n", obs.Domain, obs.Peer)
		}

	case "list":
		n := 20
		if len(args) >= 2 {
			fmt.Sscanf(args[1], "%d", &n)
		}
		doms, err := store.ListRecentDomains(ctx, n)
		if err != nil {
			fatal("list: %v", err)
		}
		for _, d := range doms {
			fmt.Printf("%-40s state=%-6s hits=%d peers=%d last=%s\n",
				d.Domain, d.State, d.HitCount, d.PeerCount, d.LastSeenAt)
		}

	case "tail":
		tailCmd(ctx, store, args[1:])

	case "prune":
		pruneCmd(ctx, store, args[1:])

	case "run":
		runCmd(ctx, store, *configPath, args[1:])

	case "hot":
		hots, err := store.ListHotEntries(ctx, time.Now().UTC())
		if err != nil {
			fatal("hot: %v", err)
		}
		for _, h := range hots {
			fmt.Println(h)
		}

	default:
		fatal("unknown command: %s", args[0])
	}
}

func tailCmd(ctx context.Context, store *storage.Store, rest []string) {
	fs := flag.NewFlagSet("tail", flag.ExitOnError)
	fromStart := fs.Bool("from-start", false, "process whole file from the beginning (default: skip existing content)")
	_ = fs.Parse(rest)
	if fs.NArg() < 1 {
		fatal("tail: missing logfile")
	}
	path := fs.Arg(0)

	lines, errs := tail.Follow(ctx, path, tail.Options{StartAtEnd: !*fromStart})

	ingested, skipped := 0, 0
	report := time.NewTicker(10 * time.Second)
	defer report.Stop()

	for {
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "tail: stopped (ingested=%d skipped=%d)\n", ingested, skipped)
			return
		case err, ok := <-errs:
			if ok && err != nil {
				fatal("tail: %v", err)
			}
		case line, ok := <-lines:
			if !ok {
				return
			}
			ev, parsed := dnsmasq.Parse(line)
			if !parsed {
				skipped++
				continue
			}
			// We count one observation per client query, not per upstream
			// forwarding (which may fire multiple times for the same request).
			// AAAA queries observe the same domain as A queries — count both;
			// the dedupe lives at the domain level.
			if ev.Action != dnsmasq.Query {
				skipped++
				continue
			}
			// Gateway's own queries (10.10.0.1) are infrastructure noise.
			if ev.Peer == "" || ev.Peer == "10.10.0.1" {
				skipped++
				continue
			}
			if _, err := watcher.Ingest(ctx, store, watcher.Event{
				Domain: ev.Domain,
				Peer:   ev.Peer,
			}); err != nil {
				fmt.Fprintf(os.Stderr, "ingest %q: %v\n", ev.Domain, err)
				continue
			}
			ingested++
		case <-report.C:
			fmt.Fprintf(os.Stderr, "tail: ingested=%d skipped=%d\n", ingested, skipped)
		}
	}
}

// pruneCmd is the operator-triggered cleanup. Use cases:
//   - migrating from a pre-exit-compare deploy where cache may hold methodological
//     FPs that the new logic would have suppressed
//   - clearing accumulated probes history without losing routing state
//   - one-off "wipe everything" reset
//
// We deliberately do NOT auto-prune on upgrade: cache_entries take effort to
// promote (50 fails/24h) and silently throwing them out would create UX gaps.
// Operators run this when they know they want to.
func pruneCmd(ctx context.Context, store *storage.Store, rest []string) {
	fs := flag.NewFlagSet("prune", flag.ExitOnError)
	cache := fs.Bool("cache", false, "delete cache_entries rows")
	hot := fs.Bool("hot", false, "delete hot_entries rows")
	probes := fs.Bool("probes", false, "delete probes rows")
	beforeStr := fs.String("before", "", "only delete rows older than this timestamp (RFC3339, e.g. 2026-04-16T11:14:00Z); empty = all")
	dryRun := fs.Bool("dry-run", false, "show what would be deleted without executing")
	_ = fs.Parse(rest)

	if !*cache && !*hot && !*probes {
		fatal("prune: need at least one of -cache, -hot, -probes")
	}
	var before time.Time
	if *beforeStr != "" {
		t, err := time.Parse(time.RFC3339, *beforeStr)
		if err != nil {
			fatal("prune: -before must be RFC3339 (e.g. 2026-04-16T11:14:00Z): %v", err)
		}
		before = t.UTC()
	}

	// Dry-run uses Count* helpers with the same WHERE shape as the prune,
	// so the preview matches the real action exactly.
	if *dryRun {
		if *cache {
			n, err := store.CountCache(ctx, before)
			if err != nil {
				fatal("count cache: %v", err)
			}
			fmt.Printf("would delete %d row(s) from cache_entries\n", n)
		}
		if *hot {
			n, err := store.CountHot(ctx, before)
			if err != nil {
				fatal("count hot: %v", err)
			}
			fmt.Printf("would delete %d row(s) from hot_entries\n", n)
		}
		if *probes {
			n, err := store.CountProbes(ctx, before)
			if err != nil {
				fatal("count probes: %v", err)
			}
			fmt.Printf("would delete %d row(s) from probes\n", n)
		}
		return
	}

	if *cache {
		n, err := store.PruneCache(ctx, before)
		if err != nil {
			fatal("prune cache: %v", err)
		}
		fmt.Printf("deleted %d row(s) from cache_entries\n", n)
	}
	if *hot {
		n, err := store.PruneHot(ctx, before)
		if err != nil {
			fatal("prune hot: %v", err)
		}
		fmt.Printf("deleted %d row(s) from hot_entries\n", n)
	}
	if *probes {
		n, err := store.PruneProbes(ctx, before)
		if err != nil {
			fatal("prune probes: %v", err)
		}
		fmt.Printf("deleted %d row(s) from probes\n", n)
	}
	// After prune, domains stuck in hot/cache/ignore without a backing row are
	// orphaned — flip them to 'new' so the engine re-probes from scratch on
	// next traffic instead of leaving them in a stale terminal state.
	if n, err := store.ResetOrphanedDomains(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warn: reset orphaned domains: %v\n", err)
	} else if n > 0 {
		fmt.Printf("reset %d orphaned domain(s) to state='new'\n", n)
	}
}

func runCmd(ctx context.Context, store *storage.Store, configPath string, rest []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fromStart := fs.Bool("from-start", false, "process whole log from the beginning")
	allow := fs.String("manual-allow", "", "path to manual allow list (optional)")
	deny := fs.String("manual-deny", "", "path to manual deny list (optional)")
	cfgFlag := fs.String("config", "", "path to YAML config (overrides other flags)")
	_ = fs.Parse(rest)

	// Config path can come from either the global -config flag or the
	// subcommand-local -config flag; subcommand wins if both set so operators
	// can override a system-wide -config for one-off runs.
	if *cfgFlag != "" {
		configPath = *cfgFlag
	}

	file, err := config.Load(configPath)
	if err != nil && err != config.ErrNotFound {
		fatal("%v", err)
	}

	logPath := fs.Arg(0)
	if file != nil && file.Logfile != "" && logPath == "" {
		logPath = file.Logfile
	}
	if logPath == "" {
		fatal("run: missing logfile (positional arg or config.logfile)")
	}

	cfg := engine.Defaults(logPath)
	cfg.FromStart = *fromStart
	cfg.ManualAllowPath = *allow
	cfg.ManualDenyPath = *deny
	applyConfigFile(&cfg, file)
	if err := engine.Run(ctx, store, cfg); err != nil {
		fatal("engine: %v", err)
	}
	fmt.Fprintln(os.Stderr, "engine: stopped")
}

// applyConfigFile overlays YAML values on top of the engine defaults and
// builds the probe backends. Zero values in the YAML leave defaults untouched —
// the operator only needs to list the knobs they actually want to change.
func applyConfigFile(cfg *engine.Config, f *config.File) {
	if f == nil {
		cfg.LocalProber = prober.NewLocal(cfg.ProbeTimeout)
		return
	}
	if f.ManualAllow != "" && cfg.ManualAllowPath == "" {
		cfg.ManualAllowPath = f.ManualAllow
	}
	if f.ManualDeny != "" && cfg.ManualDenyPath == "" {
		cfg.ManualDenyPath = f.ManualDeny
	}
	if f.Probe.Timeout > 0 {
		cfg.ProbeTimeout = f.Probe.Timeout
	}
	if f.Probe.Cooldown > 0 {
		cfg.ProbeCooldown = f.Probe.Cooldown
	}
	if f.Probe.Concurrency > 0 {
		cfg.InlineProbeConcurrency = f.Probe.Concurrency
	}
	if f.Probe.Interval > 0 {
		cfg.ProbeInterval = f.Probe.Interval
	}
	if f.Probe.Batch > 0 {
		cfg.ProbeBatch = f.Probe.Batch
	}
	if f.Scorer.Interval > 0 {
		cfg.Scorer.Interval = f.Scorer.Interval
	}
	if f.Scorer.Window > 0 {
		cfg.Scorer.Window = f.Scorer.Window
	}
	if f.Scorer.FailThreshold > 0 {
		cfg.Scorer.FailThreshold = f.Scorer.FailThreshold
	}
	if f.Ipset.Name != "" {
		cfg.IpsetName = f.Ipset.Name
	}
	if f.Ipset.ManualName != "" {
		cfg.ManualIpsetName = f.Ipset.ManualName
	}
	if f.Ipset.Interval > 0 {
		cfg.IpsetInterval = f.Ipset.Interval
	}
	if f.HotTTL > 0 {
		cfg.HotTTL = f.HotTTL
	}
	if f.DNSFreshness > 0 {
		cfg.DNSFreshness = f.DNSFreshness
	}
	if f.PublishPath != "" {
		cfg.PublishPath = f.PublishPath
	}
	if f.PublishInterval > 0 {
		cfg.PublishInterval = f.PublishInterval
	}
	if f.IgnorePeer != "" {
		cfg.IgnorePeer = f.IgnorePeer
	}
	if len(f.Extensions) > 0 {
		cfg.Extensions = f.Extensions
	}
	if f.ExtensionsPath != "" {
		cfg.ExtensionsPath = f.ExtensionsPath
	}
	cfg.LocalProber = f.BuildLocalProber(cfg.ProbeTimeout)
	cfg.RemoteProber = f.BuildRemoteProber()
}

func toStorageResult(r prober.Result) storage.ProbeResult {
	dns, tcp, tls := r.DNSOK, r.TCPOK, r.TLSOK
	return storage.ProbeResult{
		Domain:        r.Domain,
		DNSOK:         &dns,
		TCPOK:         &tcp,
		TLSOK:         &tls,
		HTTPOK:        r.HTTPOK,
		ResolvedIPs:   r.ResolvedIPs,
		FailureReason: r.FailureReason,
		LatencyMS:     r.LatencyMS,
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ladon: "+format+"\n", a...)
	os.Exit(1)
}
