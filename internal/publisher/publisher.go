// Package publisher renders the live runtime set (cache ∪ hot ∪ manual)
// into a flat artifact a downstream consumer can ingest.
//
// Phase 3: write a sorted, deduplicated list of domains to a file. The
// gateway-side ipset translation lives in Phase 5; this is just the
// "engine published its decision" boundary.
package publisher

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

// PublishDomains writes the current routable domain set to outPath atomically.
// Returns the count written.
func PublishDomains(ctx context.Context, store *storage.Store, outPath string) (int, error) {
	now := time.Now().UTC()

	hot, err := store.ListHotEntries(ctx, now)
	if err != nil {
		return 0, fmt.Errorf("list hot: %w", err)
	}
	// Cache and manual sources will arrive in later phases; for now hot is the
	// only producer, so the published set == hot. The dedupe path is already
	// in place for when those land.
	set := dedupSorted(hot)

	tmp, err := os.CreateTemp(filepath.Dir(outPath), ".publish-*.tmp")
	if err != nil {
		return 0, err
	}
	tmpPath := tmp.Name()
	w := bufio.NewWriter(tmp)
	for _, d := range set {
		if _, err := fmt.Fprintln(w, d); err != nil {
			tmp.Close()
			os.Remove(tmpPath)
			return 0, err
		}
	}
	if err := w.Flush(); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return 0, err
	}
	if err := os.Rename(tmpPath, outPath); err != nil {
		os.Remove(tmpPath)
		return 0, err
	}
	return len(set), nil
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
