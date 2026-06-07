package obs

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"":        slog.LevelInfo,
		"info":    slog.LevelInfo,
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		"warn":    slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"err":     slog.LevelError,
		"bogus":   slog.LevelInfo,
	}
	for in, want := range cases {
		if got := ParseLevel(in); got != want {
			t.Errorf("ParseLevel(%q)=%v want %v", in, got, want)
		}
	}
}

func TestBuildTextNoJournald(t *testing.T) {
	var buf bytes.Buffer
	build(Config{Level: "info", Format: "text"}, &buf, false).Info("hello", "k", "v")
	out := buf.String()
	if !strings.Contains(out, "msg=hello") || !strings.Contains(out, "k=v") {
		t.Fatalf("text output missing fields: %q", out)
	}
	if strings.HasPrefix(out, "<") {
		t.Fatalf("non-journald output must not carry a priority prefix: %q", out)
	}
	if !strings.Contains(out, "time=") {
		t.Fatalf("non-journald output should keep a timestamp: %q", out)
	}
}

func TestBuildJournaldPriorityAndNoTimestamp(t *testing.T) {
	var buf bytes.Buffer
	build(Config{Level: "info"}, &buf, true).Warn("careful")
	if out := buf.String(); !strings.HasPrefix(out, "<4>") {
		t.Fatalf("journald Warn should start with <4>: %q", out)
	} else if strings.Contains(out, "time=") {
		t.Fatalf("journald output should drop the timestamp: %q", out)
	}

	buf.Reset()
	build(Config{Level: "info"}, &buf, true).Error("boom")
	if out := buf.String(); !strings.HasPrefix(out, "<3>") {
		t.Fatalf("journald Error should start with <3>: %q", out)
	}
}

// Component loggers go through the handler's WithAttrs path — under journald the
// shared-buffer wrapper must still emit the priority prefix and the attr.
func TestJournaldWithAttrs(t *testing.T) {
	var buf bytes.Buffer
	build(Config{Level: "info"}, &buf, true) // installs as default
	Logger("scorer").Info("hi")
	out := buf.String()
	if !strings.HasPrefix(out, "<6>") || !strings.Contains(out, "component=scorer") {
		t.Fatalf("WithAttrs under journald: %q", out)
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	lg := build(Config{Level: "warn", Format: "text"}, &buf, false)
	lg.Info("quiet")
	lg.Warn("loud")
	out := buf.String()
	if strings.Contains(out, "quiet") {
		t.Fatalf("info should be filtered at level=warn: %q", out)
	}
	if !strings.Contains(out, "loud") {
		t.Fatalf("warn should pass at level=warn: %q", out)
	}
}

func TestBuildJSON(t *testing.T) {
	var buf bytes.Buffer
	build(Config{Format: "json"}, &buf, false).Info("structured", "component", "scorer", "count", 3)
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("json output not parseable: %v\n%s", err, buf.String())
	}
	if m["msg"] != "structured" || m["component"] != "scorer" {
		t.Fatalf("json fields wrong: %v", m)
	}
}
