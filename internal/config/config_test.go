package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_MissingPathReturnsNotFound(t *testing.T) {
	_, err := Load("")
	if err != ErrNotFound {
		t.Errorf("Load(\"\") = %v, want ErrNotFound", err)
	}
}

func TestLoad_DefaultsAreOK(t *testing.T) {
	// An essentially-empty YAML file should parse and validate cleanly.
	path := writeTemp(t, "---\n")
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Probe.Mode != "" {
		t.Errorf("default mode = %q, want empty (→ local)", f.Probe.Mode)
	}
	if name := f.BuildLocalProber(500 * time.Millisecond).Name(); name != "local" {
		t.Errorf("local prober = %q, want local", name)
	}
	if rp := f.BuildRemoteProber(); rp != nil {
		t.Errorf("remote prober = %v, want nil for default mode", rp)
	}
}

func TestLoad_ExitCompareMode(t *testing.T) {
	yaml := `
probe:
  mode: exit-compare
  remote:
    url: https://probe.example.com/v1/probe
    timeout: 2s
    auth_header: Authorization
    auth_value: Bearer xyz
`
	path := writeTemp(t, yaml)
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Probe.Mode != "exit-compare" {
		t.Errorf("mode = %q, want exit-compare", f.Probe.Mode)
	}
	if f.Probe.Remote.URL != "https://probe.example.com/v1/probe" {
		t.Errorf("url = %q", f.Probe.Remote.URL)
	}
	if time.Duration(f.Probe.Remote.Timeout) != 2*time.Second {
		t.Errorf("timeout = %v, want 2s", time.Duration(f.Probe.Remote.Timeout))
	}
	if name := f.BuildLocalProber(500 * time.Millisecond).Name(); name != "local" {
		t.Errorf("local prober = %q, want local even in exit-compare", name)
	}
	if name := f.BuildRemoteProber().Name(); name != "remote" {
		t.Errorf("remote prober = %q, want remote", name)
	}
}

func TestLoad_ExitCompareWithoutURL(t *testing.T) {
	yaml := `
probe:
  mode: exit-compare
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for exit-compare without url")
	}
}

func TestLoad_UnknownMode(t *testing.T) {
	yaml := `
probe:
  mode: banana
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for unknown mode")
	}
}

func TestLoad_FullShape(t *testing.T) {
	yaml := `
db: /opt/ladon/state/engine.db
logfile: /var/log/dnsmasq.log
manual_allow: /etc/ladon/manual-allow.txt
manual_deny: /etc/ladon/manual-deny.txt

probe:
  mode: local
  timeout: 1s
  cooldown: 10m
  concurrency: 16
  interval: 3s
  batch: 8

scorer:
  interval: 5m
  window: 12h
  promote_threshold: 100

ipset:
  engine_name: prod
  interval: 1m

hot_ttl: 48h
dns_freshness: 3h
ignore_peer: 10.20.0.1
`
	path := writeTemp(t, yaml)
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.DB != "/opt/ladon/state/engine.db" {
		t.Errorf("db = %q", f.DB)
	}
	if time.Duration(f.Probe.Timeout) != time.Second {
		t.Errorf("probe timeout = %v", time.Duration(f.Probe.Timeout))
	}
	if f.Scorer.PromoteThreshold != 100 {
		t.Errorf("scorer promote_threshold = %d", f.Scorer.PromoteThreshold)
	}
	if time.Duration(f.HotTTL) != 48*time.Hour {
		t.Errorf("hot_ttl = %v", time.Duration(f.HotTTL))
	}
	if f.IgnorePeer != "10.20.0.1" {
		t.Errorf("ignore_peer = %q", f.IgnorePeer)
	}
}

func TestLoad_DayDuration(t *testing.T) {
	// "7d" is what the OPNsense GUI offers for hot_ttl; the stdlib parser rejects
	// the day unit, so the daemon used to crash. It must now parse cleanly.
	f, err := Load(writeTemp(t, "hot_ttl: 7d\ndns_freshness: 1d12h\nprobe:\n  timeout: 500ms\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := time.Duration(f.HotTTL); got != 7*24*time.Hour {
		t.Errorf("hot_ttl 7d = %v, want 168h", got)
	}
	if got := time.Duration(f.DNSFreshness); got != 36*time.Hour {
		t.Errorf("dns_freshness 1d12h = %v, want 36h", got)
	}
	if got := time.Duration(f.Probe.Timeout); got != 500*time.Millisecond {
		t.Errorf("probe.timeout 500ms = %v, want 500ms", got)
	}
}

func TestParseDuration(t *testing.T) {
	cases := map[string]time.Duration{
		"7d": 7 * 24 * time.Hour, "1d12h": 36 * time.Hour, "48h": 48 * time.Hour,
		"30m": 30 * time.Minute, "2s": 2 * time.Second, "500ms": 500 * time.Millisecond,
	}
	for in, want := range cases {
		got, err := parseDuration(in)
		if err != nil || got != want {
			t.Errorf("parseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := parseDuration("1.5d"); err == nil {
		t.Error("parseDuration(1.5d) should error (fractional days unsupported)")
	}
}

func TestLoad_MissingFileIsError(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if err == ErrNotFound {
		t.Fatal("missing-file should be a real error, not ErrNotFound")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ladon.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return path
}
