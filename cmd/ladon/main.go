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

	"github.com/belotserkovtsev/ladon/internal/dnsmasq"
	"github.com/belotserkovtsev/ladon/internal/engine"
	"github.com/belotserkovtsev/ladon/internal/prober"
	"github.com/belotserkovtsev/ladon/internal/storage"
	"github.com/belotserkovtsev/ladon/internal/tail"
	"github.com/belotserkovtsev/ladon/internal/watcher"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: ladon [-db PATH] <cmd> [args]
commands:
  init-db
  probe <domain>
  observe <domain> [peer]
  list [N]
  hot
  tail [-from-start] <logfile>
  run  [-from-start] <logfile>`)
}

func main() {
	dbPath := flag.String("db", filepath.Join("state", "ladon.db"), "path to SQLite database")
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

	case "run":
		runCmd(ctx, store, args[1:])

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

func runCmd(ctx context.Context, store *storage.Store, rest []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	fromStart := fs.Bool("from-start", false, "process whole log from the beginning")
	allow := fs.String("manual-allow", "", "path to manual allow list (optional)")
	deny := fs.String("manual-deny", "", "path to manual deny list (optional)")
	_ = fs.Parse(rest)
	if fs.NArg() < 1 {
		fatal("run: missing logfile")
	}
	cfg := engine.Defaults(fs.Arg(0))
	cfg.FromStart = *fromStart
	cfg.ManualAllowPath = *allow
	cfg.ManualDenyPath = *deny
	if err := engine.Run(ctx, store, cfg); err != nil {
		fatal("engine: %v", err)
	}
	fmt.Fprintln(os.Stderr, "engine: stopped")
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
