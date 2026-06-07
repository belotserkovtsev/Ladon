// Package obs centralizes ladon's structured logging. It builds a slog.Logger
// from config (level, text/json, source) and installs it as the process
// default, so every package logs through one consistent handler with leveled,
// machine-parseable output.
//
// Under systemd the daemon's stderr is captured by journald, which stamps its
// own receive time and parses a leading "<N>" syslog priority prefix
// (SyslogLevelPrefix, on by default). When we detect we're writing to the
// journal (JOURNAL_STREAM is set in the unit's environment), we drop slog's own
// timestamp (journald already has one) and emit the priority prefix so
// `journalctl -u ladon -p warning` filters by level for free.
package obs

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Config is the logging configuration, mapped from the YAML `log:` section.
type Config struct {
	Level  string // debug|info|warn|error (default info)
	Format string // text|json (default text)
	Source bool   // include source file:line in each record

	// Journald forces the journald rendering (priority prefix + no timestamp).
	// When false, Setup auto-detects it from the JOURNAL_STREAM env var.
	Journald bool
}

// ParseLevel maps a config string to a slog.Level, defaulting to Info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error", "err":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// Setup builds the logger from cfg, installs it as slog's default, and returns
// it. journald rendering is auto-detected from the environment unless forced.
func Setup(cfg Config) *slog.Logger {
	journald := cfg.Journald || os.Getenv("JOURNAL_STREAM") != ""
	return build(cfg, os.Stderr, journald)
}

// build is the testable core of Setup — it takes an explicit writer and
// journald flag instead of reading the environment.
func build(cfg Config, w io.Writer, journald bool) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level:     ParseLevel(cfg.Level),
		AddSource: cfg.Source,
	}
	if journald {
		// journald records its own receive timestamp; ours would be redundant.
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}
	}

	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		if journald {
			h = newJournaldHandler(opts, w)
		} else {
			h = slog.NewTextHandler(w, opts)
		}
	}

	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger
}

// Logger returns a component-tagged child of the current default logger. Every
// pipeline stage takes one so log lines carry component=<stage> for filtering.
func Logger(component string) *slog.Logger {
	return slog.Default().With("component", component)
}

// journaldHandler wraps a text handler, prefixing each line with a syslog
// priority token ("<3>".."<7>") that journald turns into a real priority. The
// inner handler renders into a shared buffer under a mutex so the prefix and
// the rendered line are written to the output as one uninterrupted unit even
// under concurrent logging.
type journaldHandler struct {
	mu    *sync.Mutex
	buf   *bytes.Buffer
	inner slog.Handler
	out   io.Writer
}

func newJournaldHandler(opts *slog.HandlerOptions, out io.Writer) slog.Handler {
	buf := &bytes.Buffer{}
	return &journaldHandler{
		mu:    &sync.Mutex{},
		buf:   buf,
		inner: slog.NewTextHandler(buf, opts),
		out:   out,
	}
}

func (h *journaldHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.inner.Enabled(ctx, l)
}

func (h *journaldHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf.Reset()
	if err := h.inner.Handle(ctx, r); err != nil {
		return err
	}
	if _, err := io.WriteString(h.out, priorityPrefix(r.Level)); err != nil {
		return err
	}
	_, err := h.out.Write(h.buf.Bytes())
	return err
}

func (h *journaldHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &journaldHandler{mu: h.mu, buf: h.buf, inner: h.inner.WithAttrs(attrs), out: h.out}
}

func (h *journaldHandler) WithGroup(name string) slog.Handler {
	return &journaldHandler{mu: h.mu, buf: h.buf, inner: h.inner.WithGroup(name), out: h.out}
}

// priorityPrefix maps a slog level onto an sd-daemon syslog priority prefix
// (err=3, warning=4, info=6, debug=7).
func priorityPrefix(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "<3>"
	case l >= slog.LevelWarn:
		return "<4>"
	case l >= slog.LevelInfo:
		return "<6>"
	default:
		return "<7>"
	}
}
