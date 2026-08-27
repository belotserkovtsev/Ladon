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
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/belotserkovtsev/ladon/internal/config"
	"github.com/belotserkovtsev/ladon/internal/dnsmasq"
	"github.com/belotserkovtsev/ladon/internal/dnssrc"
	"github.com/belotserkovtsev/ladon/internal/doctor"
	"github.com/belotserkovtsev/ladon/internal/engine"
	"github.com/belotserkovtsev/ladon/internal/obs"
	"github.com/belotserkovtsev/ladon/internal/prober"
	"github.com/belotserkovtsev/ladon/internal/storage"
	"github.com/belotserkovtsev/ladon/internal/tail"
	"github.com/belotserkovtsev/ladon/internal/ui"
	"github.com/belotserkovtsev/ladon/internal/watcher"
)

// version is stamped at build time via -ldflags "-X main.version=<tag>"
// (see .github/workflows/release.yml). Defaults to "dev" for local builds.
var version = "dev"

// defaultDBPath is where a bare `ladon <cmd>` (no -db) looks for the database.
// It mirrors where each platform's installer puts it so on-box diagnostics
// (`ladon doctor`, `ladon status`) just work; the service, rc.d and OPNsense
// configd actions all pass -db explicitly and are unaffected. A relative dev
// fallback keeps `go run` working from the repo root.
func defaultDBPath() string {
	switch runtime.GOOS {
	case "freebsd": // OPNsense plugin (release/opnsense/plugin/src/etc/rc.d/ladon)
		return "/var/db/ladon/engine.db"
	case "linux": // systemd unit default prefix (release/ladon.service)
		return "/opt/ladon/state/engine.db"
	default:
		return filepath.Join("state", "ladon.db")
	}
}

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
  run  [-from-start] [-config PATH] <logfile>
  status                  what ladon is doing: activity, recent decisions, footprint
  doctor [-config PATH]   diagnosis: walks the pipeline, finds the first break
  config-check [-config PATH]  parse+validate the config, non-zero exit if bad
  why <domain>            decision trail for one domain (probes, state, ipset)
                          (these open full-screen on a terminal — q to exit; piped = plain)`)
}

func main() {
	dbPath := flag.String("db", defaultDBPath(), "path to SQLite database")
	configPath := flag.String("config", "", "path to YAML config file (optional — defaults apply if empty)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()

	if *showVersion || (len(args) > 0 && args[0] == "version") {
		fmt.Println("ladon", version)
		return
	}
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := storage.Open(*dbPath)
	if err != nil {
		fatal("%v", err)
	}
	defer store.Close()

	switch args[0] {
	case "init-db":
		if err := store.Init(ctx); err != nil {
			fatal("init: %v", err)
		}
		if st := ui.For(os.Stdout); st.Term() {
			st.Banner(os.Stdout, ui.Subtitle("init-db", version))
			fmt.Println("   " + st.Green("✔") + " база инициализирована: " + st.Dim(*dbPath))
		} else {
			fmt.Println("initialized:", *dbPath)
		}

	case "probe":
		if len(args) < 2 {
			fatal("probe: missing domain")
		}
		domain := args[1]
		if err := prober.Validate(domain); err != nil {
			fatal("%v", err)
		}
		if err := store.UpsertDomain(ctx, domain, time.Time{}); err != nil {
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
		st := ui.For(os.Stdout)
		switch {
		case obs == nil && st.Term():
			fmt.Println("   " + st.Dim("· пустой домен — пропущено"))
		case obs == nil:
			fmt.Println("(empty domain — skipped)")
		case st.Term():
			fmt.Println("   " + st.Green("✔") + " наблюдение записано: " + obs.Domain + st.Dim(" (peer="+obs.Peer+")"))
		default:
			fmt.Printf("observed %s (peer=%s)\n", obs.Domain, obs.Peer)
		}

	case "list":
		n := 20
		jsonOut := false
		for _, a := range args[1:] {
			if a == "-json" || a == "--json" {
				jsonOut = true
			} else {
				fmt.Sscanf(a, "%d", &n)
			}
		}
		doms, err := store.ListRecentDomains(ctx, n)
		if err != nil {
			fatal("list: %v", err)
		}
		if jsonOut {
			type row struct {
				Domain   string `json:"domain"`
				State    string `json:"state"`
				Hits     int    `json:"hits"`
				LastSeen string `json:"last_seen"`
			}
			out := make([]row, 0, len(doms))
			for _, d := range doms {
				out = append(out, row{d.Domain, d.State, d.HitCount, d.LastSeenAt})
			}
			_ = json.NewEncoder(os.Stdout).Encode(out)
			return
		}
		st := ui.For(os.Stdout)
		term := st.Term()
		if term {
			st.Banner(os.Stdout, ui.Subtitle("list", version))
		}
		if term && len(doms) == 0 {
			fmt.Println("   " + st.Dim("пусто"))
		}
		for _, d := range doms {
			if !term {
				fmt.Printf("%-40s state=%-6s hits=%d last=%s\n",
					d.Domain, d.State, d.HitCount, d.LastSeenAt)
				continue
			}
			fmt.Printf("   %s %s  %s\n",
				ui.Pad(d.Domain, 34), colorState(st, d.State),
				st.Dim(fmt.Sprintf("×%d  %s", d.HitCount, d.LastSeenAt)))
		}

	case "tail":
		tailCmd(ctx, store, args[1:])

	case "prune":
		pruneCmd(ctx, store, args[1:])

	case "run":
		runCmd(ctx, store, *configPath, args[1:])

	case "hot":
		jsonOut := false
		for _, a := range args[1:] {
			if a == "-json" || a == "--json" {
				jsonOut = true
			}
		}
		hots, err := store.ListHotEntries(ctx, time.Now().UTC())
		if err != nil {
			fatal("hot: %v", err)
		}
		if jsonOut {
			if hots == nil {
				hots = []string{}
			}
			_ = json.NewEncoder(os.Stdout).Encode(hots)
			return
		}
		st := ui.For(os.Stdout)
		term := st.Term()
		if term {
			st.Banner(os.Stdout, ui.Subtitle("hot", version))
		}
		if term && len(hots) == 0 {
			fmt.Println("   " + st.Dim("hot-доменов нет"))
		}
		for _, h := range hots {
			if term {
				fmt.Println("   " + st.Green("✔") + " " + h)
			} else {
				fmt.Println(h)
			}
		}

	case "status":
		statusCmd(ctx, store, *dbPath)

	case "config-check":
		// Parse + validate the config without touching the DB or network, so the
		// OPNsense Apply can fail loudly on a bad value instead of letting the
		// daemon crash silently on restart. config.Load already runs Validate and
		// the duration parser, so a bad value surfaces here as a non-zero exit.
		file, err := config.Load(*configPath)
		if err != nil && err != config.ErrNotFound {
			fatal("config: %v", err)
		}
		cfg := engine.Defaults("")
		applyConfigFile(&cfg, file)
		fmt.Println("config ok")

	case "doctor":
		doctorCmd(ctx, store, *configPath, args[1:])

	case "why":
		if len(args) < 2 {
			fatal("why: missing domain")
		}
		whyCmd(ctx, store, args[1])

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

	st := ui.For(os.Stdout)
	if st.Term() {
		st.Banner(os.Stdout, ui.Subtitle("prune", version))
	}
	// say marks a completed deletion, plan a dry-run preview line; both fall
	// back to plain text when not on a terminal.
	say := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		if st.Term() {
			fmt.Println("   " + st.Green("✔") + " " + msg)
		} else {
			fmt.Println(msg)
		}
	}
	plan := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		if st.Term() {
			fmt.Println("   " + st.Dim("· "+msg))
		} else {
			fmt.Println(msg)
		}
	}

	// Dry-run uses Count* helpers with the same WHERE shape as the prune,
	// so the preview matches the real action exactly.
	if *dryRun {
		if *cache {
			n, err := store.CountCache(ctx, before)
			if err != nil {
				fatal("count cache: %v", err)
			}
			plan("dry-run: удалилось бы %d из cache_entries", n)
		}
		if *hot {
			n, err := store.CountHot(ctx, before)
			if err != nil {
				fatal("count hot: %v", err)
			}
			plan("dry-run: удалилось бы %d из hot_entries", n)
		}
		if *probes {
			n, err := store.CountProbes(ctx, before)
			if err != nil {
				fatal("count probes: %v", err)
			}
			plan("dry-run: удалилось бы %d из probes", n)
		}
		return
	}

	if *cache {
		n, err := store.PruneCache(ctx, before)
		if err != nil {
			fatal("prune cache: %v", err)
		}
		say("удалено %d из cache_entries", n)
	}
	if *hot {
		n, err := store.PruneHot(ctx, before)
		if err != nil {
			fatal("prune hot: %v", err)
		}
		say("удалено %d из hot_entries", n)
	}
	if *probes {
		n, err := store.PruneProbes(ctx, before)
		if err != nil {
			fatal("prune probes: %v", err)
		}
		say("удалено %d из probes", n)
	}
	// Scrub domains rows whose exact domain or eTLD+1 matches a deny entry.
	// These shouldn't be tracked at all (tailer skips future events for them
	// via IsInDenyList), and leaving them in place would let the batch probe
	// worker resurrect them after ResetOrphanedDomains flips them to 'new'.
	if n, err := store.DeleteDeniedDomains(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warn: delete denied domains: %v\n", err)
	} else if n > 0 {
		say("удалено %d denied-доменов из domains", n)
	}
	// After prune, domains stuck in hot/cache/ignore without a backing row are
	// orphaned — flip them to 'new' so the engine re-probes from scratch on
	// next traffic instead of leaving them in a stale terminal state.
	if n, err := store.ResetOrphanedDomains(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warn: reset orphaned domains: %v\n", err)
	} else if n > 0 {
		say("сброшено %d orphaned-доменов в state=new", n)
	}
}

func runCmd(ctx context.Context, store *storage.Store, configPath string, rest []string) {
	// Self-migrate before the daemon touches the DB. Init is idempotent (a
	// no-op on an already-current schema), so this closes the upgrade gap where
	// swapping the binary and restarting `ladon run` without re-running init-db
	// would leave the daemon querying a column the migration hadn't added yet.
	if err := store.Init(ctx); err != nil {
		fatal("migrate: %v", err)
	}

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

	// Install the structured logger before anything logs. journald rendering is
	// auto-detected from the environment; the YAML `log:` section tunes level
	// and format. Everything below this line logs through slog.
	obs.Setup(logConfig(file))
	obs.Logger("engine").Info("starting", "version", version)

	logPath := fs.Arg(0)
	if file != nil && file.Logfile != "" && logPath == "" {
		logPath = file.Logfile
	}

	cfg := engine.Defaults(logPath)
	cfg.FromStart = *fromStart
	cfg.ManualAllowPath = *allow
	cfg.ManualDenyPath = *deny
	cfg.Version = version
	applyConfigFile(&cfg, file)
	// The logfile is only the dnsmasq tailer's input; the unbound source reads
	// a socket and ignores it. Require it only when we actually tail dnsmasq.
	if dnssrc.Resolve(cfg.DNSSource) == "dnsmasq" && cfg.LogPath == "" {
		fatal("run: missing logfile (positional arg or config.logfile)")
	}
	if err := engine.Run(ctx, store, cfg); err != nil {
		fatal("engine: %v", err)
	}
	obs.Logger("engine").Info("stopped")
}

// logConfig maps the optional YAML log section onto obs.Config. A nil file
// yields the zero value (level=info, format=text) — the production default.
func logConfig(f *config.File) obs.Config {
	if f == nil {
		return obs.Config{}
	}
	return obs.Config{Level: f.Log.Level, Format: f.Log.Format, Source: f.Log.Source}
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
		cfg.ProbeTimeout = time.Duration(f.Probe.Timeout)
	}
	if f.Probe.Cooldown > 0 {
		cfg.ProbeCooldown = time.Duration(f.Probe.Cooldown)
	}
	if f.Probe.Concurrency > 0 {
		cfg.InlineProbeConcurrency = f.Probe.Concurrency
	}
	if f.Probe.Interval > 0 {
		cfg.ProbeInterval = time.Duration(f.Probe.Interval)
	}
	if f.Probe.Batch > 0 {
		cfg.ProbeBatch = f.Probe.Batch
	}
	if f.Scorer.Interval > 0 {
		cfg.Scorer.Interval = time.Duration(f.Scorer.Interval)
	}
	if f.Scorer.Window > 0 {
		cfg.Scorer.Window = time.Duration(f.Scorer.Window)
	}
	if f.Scorer.PromoteThreshold > 0 {
		cfg.Scorer.PromoteThreshold = f.Scorer.PromoteThreshold
	}
	if f.Revalidate.Enabled != nil {
		cfg.Revalidate.Enabled = *f.Revalidate.Enabled
	}
	if f.Revalidate.Interval > 0 {
		cfg.Revalidate.Interval = time.Duration(f.Revalidate.Interval)
	}
	if f.Revalidate.Batch > 0 {
		cfg.Revalidate.Batch = f.Revalidate.Batch
	}
	if f.Revalidate.Streak > 0 {
		cfg.Revalidate.Streak = f.Revalidate.Streak
	}
	if f.Ipset.EngineName != "" {
		cfg.IpsetName = f.Ipset.EngineName
	}
	if f.Ipset.ManualName != "" {
		cfg.ManualIpsetName = f.Ipset.ManualName
	}
	if f.Ipset.CIDRName != "" {
		cfg.CIDRIpsetName = f.Ipset.CIDRName
	}
	if f.Ipset.Interval > 0 {
		cfg.IpsetInterval = time.Duration(f.Ipset.Interval)
	}
	if f.HotTTL > 0 {
		cfg.HotTTL = time.Duration(f.HotTTL)
	}
	if f.DNSFreshness > 0 {
		cfg.DNSFreshness = time.Duration(f.DNSFreshness)
	}
	if f.FamilyConfirmThreshold > 0 {
		cfg.FamilyConfirmThreshold = f.FamilyConfirmThreshold
	}
	if f.IgnorePeer != "" {
		cfg.IgnorePeer = f.IgnorePeer
	}
	if f.ManageDNSMasq != nil {
		cfg.ManageDNSMasq = *f.ManageDNSMasq
	}
	if len(f.AllowExtensions) > 0 {
		cfg.AllowExtensions = f.AllowExtensions
	}
	if len(f.DenyExtensions) > 0 {
		cfg.DenyExtensions = f.DenyExtensions
	}
	if f.ExtensionsPath != "" {
		cfg.ExtensionsPath = f.ExtensionsPath
	}
	cfg.LocalProber = f.BuildLocalProber(cfg.ProbeTimeout)
	cfg.RemoteProber = f.BuildRemoteProber()
}

// statusCmd shows what ladon has been doing — activity, recent tunnel
// decisions, failure-code mix, and the tunnel footprint. Distinct from doctor
// (which judges health): status is read-only insight, no verdict, no env probe.
func statusCmd(ctx context.Context, store *storage.Store, dbPath string) {
	if err := store.Init(ctx); err != nil {
		fatal("status: %v", err)
	}
	// Full-screen on a terminal; plain inline when piped/redirected.
	if ui.For(os.Stdout).Term() {
		var b strings.Builder
		st := ui.Forced(true)
		st.Banner(&b, ui.Subtitle("status", version))
		statusBody(ctx, store, st, &b, dbPath)
		ui.Screen(b.String())
		return
	}
	st := ui.For(os.Stdout)
	st.Banner(os.Stdout, ui.Subtitle("status", version))
	statusBody(ctx, store, st, os.Stdout, dbPath)
}

func statusBody(ctx context.Context, store *storage.Store, st ui.Style, w io.Writer, dbPath string) {
	now := time.Now().UTC()
	meta, _ := store.AllMeta(ctx)

	// --- движок: identity + uptime ---
	st.Section(w, "ДВИЖОК")
	ver := version
	if m, ok := meta["version"]; ok {
		ver = m.Value
	}
	up := "—"
	if m, ok := meta["started_at"]; ok {
		if t, valid, err := storage.ParseTime(m.Value); err == nil && valid {
			up = uptime(now.Sub(t))
		}
	}
	pid := "—"
	if m, ok := meta["pid"]; ok {
		pid = m.Value
	}
	st.Info(w, "версия", ver+"  ·  аптайм "+up+"  ·  pid "+pid)
	if m, ok := meta["last_tick_at"]; ok {
		st.Info(w, "последний тик", metaAgo(m.Value, now)+" назад")
	} else {
		st.Info(w, "последний тик", "нет heartbeat — демон не запущен?")
	}
	fmt.Fprintln(w)

	// --- активность за час ---
	st.Section(w, "АКТИВНОСТЬ · за час")
	since := now.Add(-time.Hour)
	if n, err := store.CountObservationsSince(ctx, since); err == nil {
		st.Info(w, "наблюдений", fmt.Sprintf("%d доменов", n))
	}
	if total, blocked, clear, err := store.RecentProbeStats(ctx, since); err == nil {
		st.Info(w, "проб", fmt.Sprintf("%d  (заблокировано %d · чисто %d)", total, blocked, clear))
	}
	if codes, err := store.TopFailureCodes(ctx, since, 5); err == nil && len(codes) > 0 {
		parts := make([]string, 0, len(codes))
		for _, c := range codes {
			parts = append(parts, fmt.Sprintf("%s %d", c.Code, c.N))
		}
		st.Info(w, "топ-коды", strings.Join(parts, " · "))
	}
	fmt.Fprintln(w)

	// --- свежие решения ---
	st.Section(w, "СВЕЖИЕ РЕШЕНИЯ · ушли в туннель")
	if decs, err := store.RecentDecisions(ctx, 6); err == nil && len(decs) > 0 {
		for _, d := range decs {
			age := d.At
			if t, valid, perr := storage.ParseTime(d.At); perr == nil && valid {
				age = ago(now.Sub(t))
			}
			tier := st.Green(ui.Pad(d.Tier, 6))
			if d.Tier == "hot" {
				tier = st.Yellow(ui.Pad(d.Tier, 6))
			}
			fmt.Fprintf(w, "   %s %s %s  %s\n",
				st.Dim(ui.Pad(age, 5)), tier, ui.Pad(d.Domain, 30), st.Dim(shortReason(d.Reason)))
		}
	} else {
		st.Info(w, "—", "пока ничего не туннелировалось")
	}
	fmt.Fprintln(w)

	// --- туннель: footprint ---
	st.Section(w, "ТУННЕЛЬ · footprint")
	counts, _ := store.CountDomainsByState(ctx)
	st.Info(w, "домены", fmt.Sprintf("hot %d · cache %d · covered %d · ignore %d · new %d",
		counts["hot"], counts["cache"], counts["covered"], counts["ignore"], counts["new"]))
	if m, ok := meta["ipset_engine_size"]; ok {
		st.Info(w, "набор engine", m.Value+" IP")
	}
	if fams, err := store.TopFamilies(ctx, 5); err == nil && len(fams) > 0 {
		parts := make([]string, 0, len(fams))
		for _, f := range fams {
			parts = append(parts, fmt.Sprintf("%s ×%d", f.Family, f.N))
		}
		st.Info(w, "топ-семьи", strings.Join(parts, " · "))
	}
	if sz := dbSize(dbPath); sz != "" {
		st.Info(w, "база", sz)
	}
	fmt.Fprintln(w)
}

// uptime renders a duration as a coarse "Xд Yч" / "Yч Zм" / "Zм".
func uptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d.Hours()) / 24
	hrs := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dд %dч", days, hrs)
	case hrs > 0:
		return fmt.Sprintf("%dч %dм", hrs, mins)
	default:
		return fmt.Sprintf("%dм", mins)
	}
}

// shortReason condenses a verbose hot/cache reason into a readable token: the
// failure code (and "repeated_block" for scorer promotions), dropping the raw
// error text and IPs that bloat the reason string.
func shortReason(r string) string {
	code := ""
	if i := strings.Index(r, "local:"); i >= 0 {
		rest := r[i+len("local:"):]
		end := len(rest)
		for j, ch := range rest {
			if ch == ':' || ch == '|' || ch == ' ' {
				end = j
				break
			}
		}
		code = rest[:end]
	}
	switch {
	case strings.HasPrefix(r, "repeated_block"):
		if code != "" {
			return "repeated_block · " + code
		}
		return "repeated_block"
	case code != "":
		return code
	case len([]rune(r)) > 44:
		return string([]rune(r)[:44]) + "…"
	default:
		return r
	}
}

// dbSize reports the engine.db (and WAL) size, or "" if it can't stat them.
func dbSize(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	fi, err := os.Stat(dbPath)
	if err != nil {
		return ""
	}
	out := filepath.Base(dbPath) + " " + humanBytes(fi.Size())
	if wfi, err := os.Stat(dbPath + "-wal"); err == nil && wfi.Size() > 0 {
		out += " (WAL " + humanBytes(wfi.Size()) + ")"
	}
	return out
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%d МБ", n/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d КБ", n/(1<<10))
	default:
		return fmt.Sprintf("%d Б", n)
	}
}

// doctorCmd runs the full pipeline diagnosis and exits with the report's code
// (0 healthy, 1 degraded, 2 broken) so it's usable in scripts and monitors.
func doctorCmd(ctx context.Context, store *storage.Store, configPath string, rest []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	cfgFlag := fs.String("config", "", "path to YAML config (for ipset names)")
	jsonOut := fs.Bool("json", false, "emit JSON instead of the human report")
	_ = fs.Parse(rest)
	if *cfgFlag != "" {
		configPath = *cfgFlag
	}
	if err := store.Init(ctx); err != nil {
		fatal("doctor: %v", err)
	}
	file, err := config.Load(configPath)
	if err != nil && err != config.ErrNotFound {
		fatal("doctor: %v", err)
	}
	cfg := engine.Defaults("")
	applyConfigFile(&cfg, file)

	rep := doctor.Run(ctx, store, doctor.Params{
		Version:         version,
		IpsetEngineName: cfg.IpsetName,
		IpsetManualName: cfg.ManualIpsetName,
		IpsetCIDRName:   cfg.CIDRIpsetName,
		ExpiryInterval:  cfg.ExpiryInterval,
		ServiceName:     "ladon",
		ProbeService:    true,
		ProbeIpset:      true,
	})
	switch {
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	case ui.For(os.Stdout).Term():
		ui.Screen(rep.ScreenContent())
	default:
		rep.Render(os.Stdout)
	}
	os.Exit(rep.Exit)
}

// whyCmd prints the decision trail for one domain: current state, backing tier,
// observed IPs, and the recent probe history — answering "why is X (not)
// tunneled?" from the durable record.
func whyCmd(ctx context.Context, store *storage.Store, domain string) {
	if err := store.Init(ctx); err != nil {
		fatal("why: %v", err)
	}
	if ui.For(os.Stdout).Term() {
		var b strings.Builder
		st := ui.Forced(true)
		st.Banner(&b, ui.Subtitle("why", version))
		whyBody(ctx, store, st, &b, domain)
		ui.Screen(b.String())
		return
	}
	st := ui.For(os.Stdout)
	if st.Term() {
		st.Banner(os.Stdout, ui.Subtitle("why", version))
	}
	whyBody(ctx, store, st, os.Stdout, domain)
}

func whyBody(ctx context.Context, store *storage.Store, st ui.Style, w io.Writer, domain string) {
	d, ok, err := store.GetDomain(ctx, domain)
	if err != nil {
		fatal("why: %v", err)
	}
	if !ok {
		fmt.Fprintln(w, "  "+st.Dim(domain+" не отслеживается (нет в базе)."))
		return
	}

	st.Section(w, "ДОМЕН")
	st.Info(w, "домен", d.Domain)
	st.Info(w, "eTLD+1", dash(d.ETLDPlusOne))
	st.Info(w, "состояние", d.State)
	st.Info(w, "замечен", dash(d.FirstSeenAt)+" … "+dash(d.LastSeenAt)+" (×"+strconv.Itoa(d.HitCount)+")")
	if d.CooldownUntil != "" {
		st.Info(w, "cooldown", "до "+d.CooldownUntil)
	}
	if exp, reason, ok, _ := store.HotEntryFor(ctx, domain); ok {
		st.Info(w, "hot", "до "+exp+" — "+dash(reason))
	}
	if at, reason, ok, _ := store.CacheEntryFor(ctx, domain); ok {
		st.Info(w, "cache", "с "+at+" — "+dash(reason))
	}
	if ips, _ := store.LookupAllIPs(ctx, domain); len(ips) > 0 {
		st.Info(w, "IP ("+strconv.Itoa(len(ips))+")", strings.Join(ips, ", "))
	}
	fmt.Fprintln(w)

	st.Section(w, "ПОСЛЕДНИЕ ПРОБЫ")
	probes, _ := store.RecentProbesForDomain(ctx, domain, 10)
	if len(probes) == 0 {
		st.Info(w, "—", "проб ещё не было")
	} else {
		for _, p := range probes {
			dns, tcp, tls, http := p.Flags()
			line := fmt.Sprintf("%s  dns=%-2s tcp=%-2s tls=%-2s http=%-2s  %s",
				p.CreatedAt, dns, tcp, tls, http, dash(p.FailureReason))
			switch p.Verdict {
			case "blocked":
				fmt.Fprintln(w, "   "+st.Red("✖")+" "+line+"  "+st.Red("blocked"))
			case "clear":
				fmt.Fprintln(w, "   "+st.Green("✔")+" "+line+"  "+st.Green("clear"))
			default:
				fmt.Fprintln(w, "   "+st.Dim("·")+" "+line)
			}
		}
	}
	fmt.Fprintln(w)

	switch d.State {
	case "hot", "cache":
		fmt.Fprintln(w, "  "+st.Green("▸ туннелируется")+st.Dim(" (входит в ladon_engine)."))
	case "covered":
		fmt.Fprintln(w, "  "+st.Green("▸ туннелируется")+st.Dim(" через семью "+dash(d.ETLDPlusOne)+" (covered — отдельно не пробится)."))
	case "ignore":
		fmt.Fprintln(w, "  "+st.Yellow("▸ не туннелируется")+st.Dim(" — последняя проба сочла путь рабочим (clear)."))
		fmt.Fprintln(w, "    "+st.Dim("если сайт реально не открывается — возможна L7/cert-слепота; добавь в manual-allow."))
	case "new":
		fmt.Fprintln(w, "  "+st.Dim("▸ ещё не классифицирован (ждёт пробы)."))
	}
}

// ago renders a duration as a compact RU age token (Nс/Nм/Nч/Nд).
func ago(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%dс", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dм", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dч", int(d.Hours()))
	default:
		return fmt.Sprintf("%dд", int(d.Hours()/24))
	}
}

// metaAgo parses a storage-layout timestamp and renders its age, or echoes the
// raw value if it doesn't parse.
func metaAgo(value string, now time.Time) string {
	t, ok, err := storage.ParseTime(value)
	if err != nil || !ok {
		return value
	}
	return ago(now.Sub(t))
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// colorState tints a padded domain-state token by what it means for the domain:
// tunneled tiers (cache/hot/covered) green, ignore dim, new yellow.
func colorState(st ui.Style, state string) string {
	pad := ui.Pad(state, 8)
	switch state {
	case "cache", "hot", "covered":
		return st.Green(pad)
	case "ignore":
		return st.Dim(pad)
	case "new":
		return st.Yellow(pad)
	default:
		return pad
	}
}

func toStorageResult(r prober.Result) storage.ProbeResult {
	dns, tcp, tls := r.DNSOK, r.TCPOK, r.TLSOK
	return storage.ProbeResult{
		Domain:        r.Domain,
		DNSOK:         &dns,
		TCPOK:         &tcp,
		TLSOK:         &tls,
		HTTPOK:        r.HTTPOK,
		FailureReason: r.FailureReason,
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "ladon: "+format+"\n", a...)
	os.Exit(1)
}
