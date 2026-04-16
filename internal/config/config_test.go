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
	p := f.BuildProber(500 * time.Millisecond)
	if p.Name() != "local" {
		t.Errorf("default prober = %q, want local", p.Name())
	}
}

func TestLoad_RemoteMode(t *testing.T) {
	yaml := `
probe:
  mode: remote
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
	if f.Probe.Mode != "remote" {
		t.Errorf("mode = %q, want remote", f.Probe.Mode)
	}
	if f.Probe.Remote.URL != "https://probe.example.com/v1/probe" {
		t.Errorf("url = %q", f.Probe.Remote.URL)
	}
	if f.Probe.Remote.Timeout != 2*time.Second {
		t.Errorf("timeout = %v, want 2s", f.Probe.Remote.Timeout)
	}
	p := f.BuildProber(500 * time.Millisecond)
	if p.Name() != "remote" {
		t.Errorf("prober = %q, want remote", p.Name())
	}
}

func TestLoad_RemoteModeWithoutURL(t *testing.T) {
	yaml := `
probe:
  mode: remote
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validation error for remote without url")
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
  fail_threshold: 100

ipset:
  name: prod
  interval: 1m

hot_ttl: 48h
dns_freshness: 3h
publish_path: /opt/ladon/state/published.txt
publish_interval: 5s
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
	if f.Probe.Timeout != time.Second {
		t.Errorf("probe timeout = %v", f.Probe.Timeout)
	}
	if f.Scorer.FailThreshold != 100 {
		t.Errorf("scorer threshold = %d", f.Scorer.FailThreshold)
	}
	if f.HotTTL != 48*time.Hour {
		t.Errorf("hot_ttl = %v", f.HotTTL)
	}
	if f.IgnorePeer != "10.20.0.1" {
		t.Errorf("ignore_peer = %q", f.IgnorePeer)
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
