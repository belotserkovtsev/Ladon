// Snapshot publishing for non-ipset consumers: writes a JSON artifact
// describing the current routable set (hot ∪ cache ∪ manual-deny) with
// per-domain resolved IPs. The iOS SDK reads this file from its app-group
// container and rebuilds its in-memory IP lookup set on each change.
//
// The server-side PublishDomains (publisher.go) emits a flat domain list
// that the gateway's ipset-apply scripts consume; PublishSnapshotJSON is
// its richer, client-side sibling. Both coexist in the same package and
// may be wired in parallel when the operator wants both outputs.

package publisher

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

// SnapshotEntry is one routable domain with its currently-resolved v4 IPs.
// Empty IPs mean we've classified the domain but have no fresh dns_cache
// observation — the consumer can still match by domain (e.g. for DNS-level
// interception) but can't match by IP at the packet layer.
type SnapshotEntry struct {
	Domain string   `json:"domain"`
	IPs    []string `json:"ips,omitempty"`
}

// Snapshot is the on-disk JSON shape. Versioned so consumers can detect
// incompatible changes when the schema evolves.
type Snapshot struct {
	Version     int             `json:"version"`
	GeneratedAt time.Time       `json:"generated_at"`
	Hot         []SnapshotEntry `json:"hot"`
	Cache       []SnapshotEntry `json:"cache"`
	ManualDeny  []SnapshotEntry `json:"manual_deny"`
}

// SnapshotVersion bumps whenever the JSON shape gains or loses a field that
// consumers care about. New optional fields don't require a bump; renames
// or removals do.
const SnapshotVersion = 1

// PublishSnapshotJSON reads the current hot/cache/manual-deny sets from the
// store, joins each domain with its fresh dns_cache IPs, and writes a JSON
// snapshot to outPath atomically (tmp + rename — same pattern as
// PublishDomains). freshSince caps dns_cache staleness: IPs first seen
// before freshSince are omitted, so consumers never route to an IP that
// may have rotated away from the domain.
func PublishSnapshotJSON(ctx context.Context, store *storage.Store, outPath string, freshSince time.Time) error {
	now := time.Now().UTC()

	hotDomains, err := store.ListHotEntries(ctx, now)
	if err != nil {
		return fmt.Errorf("list hot: %w", err)
	}
	cacheDomains, err := store.ListCacheEntries(ctx)
	if err != nil {
		return fmt.Errorf("list cache: %w", err)
	}
	denyDomains, err := store.ListManualByList(ctx, "deny")
	if err != nil {
		return fmt.Errorf("list manual deny: %w", err)
	}

	snap := Snapshot{
		Version:     SnapshotVersion,
		GeneratedAt: now,
		Hot:         buildEntries(ctx, store, hotDomains, freshSince),
		Cache:       buildEntries(ctx, store, cacheDomains, freshSince),
		ManualDeny:  buildEntries(ctx, store, denyDomains, freshSince),
	}

	return writeAtomic(outPath, &snap)
}

// buildEntries turns a domain list into SnapshotEntry records, joining
// each domain with its current fresh IPs from dns_cache. On per-domain
// lookup error we skip the IPs but keep the entry — consumers may still
// want the domain for name-level matching. Output is sorted by domain for
// deterministic diffs across snapshot versions.
func buildEntries(ctx context.Context, store *storage.Store, domains []string, freshSince time.Time) []SnapshotEntry {
	if len(domains) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(domains))
	out := make([]SnapshotEntry, 0, len(domains))
	for _, d := range domains {
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		ips, _ := store.LookupIPs(ctx, d, freshSince)
		out = append(out, SnapshotEntry{Domain: d, IPs: ips})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// writeAtomic marshals snap into outPath via a sibling tmp file + rename.
// Rename is atomic on the same filesystem, so a reader watching outPath
// either sees the previous complete snapshot or the new complete one —
// never a partial write.
func writeAtomic(outPath string, snap *Snapshot) error {
	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".snapshot-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	w := bufio.NewWriter(tmp)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}
