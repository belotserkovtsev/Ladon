package tail

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func writeFile(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func nextLine(t *testing.T, lines <-chan string, errs <-chan error) string {
	t.Helper()
	select {
	case l := <-lines:
		return l
	case err := <-errs:
		t.Fatalf("tail error: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for line")
	}
	return ""
}

func fastFollow(t *testing.T, path string) (context.CancelFunc, <-chan string, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	lines, errs := Follow(ctx, path, Options{
		PollInterval:     10 * time.Millisecond,
		ReopenCheckEvery: 10 * time.Millisecond,
	})
	return cancel, lines, errs
}

// TestFollow_SurvivesCopytruncate is the regression for the missed-block bug:
// logrotate copytruncate resets the file in place (same inode), and before the
// fix the tailer kept its stale offset and silently dropped every post-rotation
// line until the file regrew past it.
func TestFollow_SurvivesCopytruncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.log")
	writeFile(t, path, "line1\n")

	cancel, lines, errs := fastFollow(t, path)
	defer cancel()

	if got := nextLine(t, lines, errs); got != "line1" {
		t.Fatalf("got %q, want line1", got)
	}
	appendFile(t, path, "line2\n")
	if got := nextLine(t, lines, errs); got != "line2" {
		t.Fatalf("got %q, want line2", got)
	}

	// Copytruncate: content copied away, original truncated in place (same
	// inode), then new lines appended from offset 0.
	if err := os.Truncate(path, 0); err != nil {
		t.Skipf("truncate-in-place not supported here: %v", err)
	}
	appendFile(t, path, "line3\n")

	if got := nextLine(t, lines, errs); got != "line3" {
		t.Fatalf("post-copytruncate got %q, want line3 (dropped by stale offset?)", got)
	}
}

// TestFollow_DoesNotSplitTornLine ensures a write that lands mid-line at EOF
// (no terminating newline yet) is held rather than emitted as a truncated line
// and then split in two. Before the fix, ReadString returned the partial at EOF
// and the loop emitted it as if complete.
func TestFollow_DoesNotSplitTornLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.log")
	writeFile(t, path, "")

	cancel, lines, errs := fastFollow(t, path)
	defer cancel()

	// First half of a line, no newline — let the tailer hit EOF on it.
	appendFile(t, path, "developers.openai.")
	// While it lacks a terminating newline it must be HELD, not emitted. This
	// also gives the tailer time (several poll/reopen ticks) to actually hit EOF
	// on the partial, so the torn path is exercised independent of timing.
	select {
	case l := <-lines:
		t.Fatalf("partial line emitted early: %q", l)
	case err := <-errs:
		t.Fatalf("tail error: %v", err)
	case <-time.After(120 * time.Millisecond):
	}
	// Complete the line.
	appendFile(t, path, "com query\n")

	if got := nextLine(t, lines, errs); got != "developers.openai.com query" {
		t.Fatalf("got %q, want reassembled line (torn-line split?)", got)
	}

	// A following whole line still flows normally.
	appendFile(t, path, "second\n")
	if got := nextLine(t, lines, errs); got != "second" {
		t.Fatalf("got %q, want second", got)
	}
}

// TestFollow_SurvivesInodeRotation locks the existing create/rename rotation
// path. Skipped on Windows where inode() is a no-op (rotation detection there
// relies solely on the size-based copytruncate path).
func TestFollow_SurvivesInodeRotation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("inode-based rotation detection is a no-op on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "dnsmasq.log")
	writeFile(t, path, "a\n")

	cancel, lines, errs := fastFollow(t, path)
	defer cancel()

	if got := nextLine(t, lines, errs); got != "a" {
		t.Fatalf("got %q, want a", got)
	}

	// create-rotation: move the old file aside, create a fresh one (new inode).
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, "b\n")

	if got := nextLine(t, lines, errs); got != "b" {
		t.Fatalf("post-rotation got %q, want b", got)
	}
}
