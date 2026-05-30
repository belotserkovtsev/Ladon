// Package tail follows a log file like `tail -F`, surviving truncation
// (in place / logrotate copytruncate), rotation (inode change), and brief
// disappearance.
//
// Unlike a plain polling tail, EOF waits block on an fsnotify watcher, so
// new data is dispatched within kernel-event latency (~sub-millisecond on
// Linux) rather than waiting out a poll interval. A fallback timer still
// fires periodically so rotation detection works even when fsnotify misses
// an event (e.g. on a filesystem that doesn't support inotify).
package tail

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Options tunes the tailer.
type Options struct {
	// PollInterval bounds the wait when fsnotify is silent. Even with
	// kernel events we need a timer as safety net for rotation on exotic
	// filesystems. Much smaller than the old pure-poll version.
	PollInterval time.Duration
	// StartAtEnd controls the initial seek: true = skip existing content.
	StartAtEnd bool
	// ReopenCheckEvery throttles inode checks.
	ReopenCheckEvery time.Duration
}

// Follow opens path and emits each line on the returned channel.
// The channel is closed only when ctx is cancelled.
func Follow(ctx context.Context, path string, opts Options) (<-chan string, <-chan error) {
	if opts.PollInterval == 0 {
		// Only fires when fsnotify is silent — effectively the rotation-
		// detection cadence on broken watchers. Default generously.
		opts.PollInterval = 500 * time.Millisecond
	}
	if opts.ReopenCheckEvery == 0 {
		opts.ReopenCheckEvery = 2 * time.Second
	}

	lines := make(chan string, 128)
	errs := make(chan error, 1)

	go func() {
		defer close(lines)
		defer close(errs)

		var (
			f        *os.File
			reader   *bufio.Reader
			curIno   uint64
			lastStat time.Time
		)
		defer func() {
			if f != nil {
				f.Close()
			}
		}()

		// fsnotify watcher — may fail on systems without inotify/etc.;
		// we degrade to pure polling if so.
		watcher, werr := fsnotify.NewWatcher()
		if werr == nil {
			defer watcher.Close()
		}

		openFile := func() error {
			if f != nil {
				f.Close()
				if watcher != nil {
					_ = watcher.Remove(path)
				}
			}
			var err error
			f, err = os.Open(path)
			if err != nil {
				return err
			}
			if opts.StartAtEnd {
				if _, err := f.Seek(0, io.SeekEnd); err != nil {
					return err
				}
				opts.StartAtEnd = false
			}
			reader = bufio.NewReader(f)
			fi, err := f.Stat()
			if err == nil {
				curIno = inode(fi)
			}
			lastStat = time.Now()
			if watcher != nil {
				_ = watcher.Add(path)
			}
			return nil
		}

		if err := openFile(); err != nil {
			errs <- err
			return
		}

		// events channel is nil when fsnotify is unavailable, which makes the
		// select below fall through to the timer — same semantics as before.
		var events <-chan fsnotify.Event
		if watcher != nil {
			events = watcher.Events
		}

		// pending holds a partial line read at EOF (no terminating newline yet).
		// We only emit newline-terminated lines, so a torn write — an fsnotify
		// tick landing mid-line — never splits one log line into two events. The
		// fragment is carried until the rest arrives, and dropped on rotation
		// (the truncated/replaced content it belonged to is gone).
		var pending string

		for {
			if err := ctx.Err(); err != nil {
				return
			}

			chunk, err := reader.ReadString('\n')
			if err == nil {
				line := pending + chunk
				pending = ""
				line = line[:len(line)-1] // drop the trailing '\n'
				if len(line) > 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
				continue
			}
			if !errors.Is(err, io.EOF) {
				errs <- err
				return
			}
			// EOF: stash the unterminated remainder (if any) until more arrives.
			pending += chunk

			// EOF — wait for a write event or timer tick.
			timer := time.NewTimer(opts.PollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-events:
				// Drain any additional events that arrived during processing —
				// they all mean the same thing ("there might be new data").
				drainEvents(events)
				timer.Stop()
			case <-timer.C:
			}

			if time.Since(lastStat) >= opts.ReopenCheckEvery {
				lastStat = time.Now()
				// Create/rename rotation (logrotate default): a new inode sits
				// at the path → reopen fresh.
				if fi, err := os.Stat(path); err == nil && inode(fi) != curIno {
					_ = openFile()
					pending = "" // new inode → the old partial line is gone
					if watcher != nil {
						events = watcher.Events
					}
				} else if truncatedBelowReader(f) {
					// Copytruncate / truncate-in-place rotation: same inode, but
					// the file shrank below our read offset, so it was truncated
					// out from under us. The pre-truncate content — including any
					// buffered partial — is gone, so drop the partial regardless
					// of whether the seek succeeds (a failed seek is retried on
					// the next tick). Then seek back to the start and reset the
					// buffered reader so we pick up the post-truncation content
					// instead of silently dropping lines until the file regrew
					// past the stale offset.
					pending = ""
					if _, err := f.Seek(0, io.SeekStart); err == nil {
						reader.Reset(f)
					}
				}
			}
		}
	}()

	return lines, errs
}

func drainEvents(ch <-chan fsnotify.Event) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// truncatedBelowReader reports whether f was truncated in place: its current
// size is smaller than our read position. For an append-only log that can only
// happen when the file was reset (logrotate copytruncate). The inode is
// unchanged in that case, so the inode comparison can't detect it. We compare
// the file descriptor's offset (advanced by bufio's read-ahead, so it sits at
// the last byte we fetched) against the live size; only a shrink trips it, so
// normal growth never false-positives.
func truncatedBelowReader(f *os.File) bool {
	if f == nil {
		return false
	}
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Size() < pos
}
