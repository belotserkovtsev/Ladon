// Package manual loads allow/deny domain lists from plain text files into
// manual_entries. Each line is one domain; blanks and '#' comments are
// skipped. Loading is additive — removing a line from the file does NOT
// remove the row from the DB (operator explicitly clears if needed).
package manual

import (
	"bufio"
	"context"
	"os"
	"strings"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

// Load reads path and upserts each domain into manual_entries under listName.
// Missing or unreadable files are a no-op — callers choose whether to care.
// Returns the number of entries actually upserted.
func Load(ctx context.Context, store *storage.Store, path, listName string) (int, error) {
	if path == "" {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := strings.ToLower(strings.TrimRight(line, "."))
		if domain == "" {
			continue
		}
		if err := store.UpsertManual(ctx, domain, listName); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}
