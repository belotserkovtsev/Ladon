// split-engine CLI.
//
// Subcommands:
//
//	init-db         create/update the SQLite schema
//	probe <domain>  run a DNS/TCP/TLS probe and persist the result
//	observe <d>     record a synthetic DNS observation (for dev)
//	list [N]        show the N most recent domains (default 20)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/belotserkovtsev/split-engine/internal/prober"
	"github.com/belotserkovtsev/split-engine/internal/storage"
	"github.com/belotserkovtsev/split-engine/internal/watcher"
)

func usage() {
	fmt.Fprintln(os.Stderr, `usage: split-engine [-db PATH] <cmd> [args]
commands:
  init-db
  probe <domain>
  observe <domain> [peer]
  list [N]`)
}

func main() {
	dbPath := flag.String("db", filepath.Join("state", "split-engine.db"), "path to SQLite database")
	flag.Usage = usage
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	ctx := context.Background()
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
		// Ensure the domain row exists so last_probe_id has somewhere to land.
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

	default:
		fatal("unknown command: %s", args[0])
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
		ResolvedIPs:   r.ResolvedIPs,
		FailureReason: r.FailureReason,
		LatencyMS:     r.LatencyMS,
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "split-engine: "+format+"\n", a...)
	os.Exit(1)
}
