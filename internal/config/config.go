// Package config loads ladon's YAML config file and hands back an engine.Config
// plus a probe backend chosen by the file.
//
// The config file is entirely optional — when no -config flag is given, the
// CLI falls back to the same flags it has always accepted and runs with a
// LocalProber. The config file only matters when the operator wants to switch
// probe backend or tune knobs the CLI doesn't expose.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/belotserkovtsev/ladon/internal/prober"
	"gopkg.in/yaml.v3"
)

// File mirrors the on-disk YAML shape. All fields are optional — unset values
// fall through to the engine defaults.
type File struct {
	DB          string `yaml:"db"`
	Logfile     string `yaml:"logfile"`
	ManualAllow string `yaml:"manual_allow"`
	ManualDeny  string `yaml:"manual_deny"`

	Probe  ProbeSection  `yaml:"probe"`
	Scorer ScorerSection `yaml:"scorer"`
	Ipset  IpsetSection  `yaml:"ipset"`

	HotTTL          time.Duration `yaml:"hot_ttl"`
	DNSFreshness    time.Duration `yaml:"dns_freshness"`
	PublishPath     string        `yaml:"publish_path"`
	PublishInterval time.Duration `yaml:"publish_interval"`
	IgnorePeer      string        `yaml:"ignore_peer"`
}

// ProbeSection covers both the shared probe tuning and the backend selector.
type ProbeSection struct {
	Mode        string        `yaml:"mode"` // "local" (default) | "remote"
	Timeout     time.Duration `yaml:"timeout"`
	Cooldown    time.Duration `yaml:"cooldown"`
	Concurrency int           `yaml:"concurrency"`
	Interval    time.Duration `yaml:"interval"`
	Batch       int           `yaml:"batch"`

	Remote RemoteSection `yaml:"remote"`
}

// RemoteSection configures the RemoteProber. Only consulted when mode=remote.
type RemoteSection struct {
	URL        string        `yaml:"url"`
	Timeout    time.Duration `yaml:"timeout"`
	AuthHeader string        `yaml:"auth_header"`
	AuthValue  string        `yaml:"auth_value"`
}

// ScorerSection mirrors scorer.Config.
type ScorerSection struct {
	Interval      time.Duration `yaml:"interval"`
	Window        time.Duration `yaml:"window"`
	FailThreshold int           `yaml:"fail_threshold"`
}

// IpsetSection mirrors the ipset knobs.
type IpsetSection struct {
	Name     string        `yaml:"name"`
	Interval time.Duration `yaml:"interval"`
}

// Load reads and parses a YAML file. Returns ErrNotFound if the path is empty
// so callers can fall through to defaults. Missing files at non-empty paths
// are a real error — the operator asked for a config and we couldn't open it.
func Load(path string) (*File, error) {
	if path == "" {
		return nil, ErrNotFound
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("config %q: %w", path, err)
	}
	return &f, nil
}

// Validate checks the subset of fields where an invalid value is worse than a
// missing one. Most fields are allowed to be empty — Defaults fill them in.
func (f *File) Validate() error {
	switch f.Probe.Mode {
	case "", "local", "remote":
		// ok
	default:
		return fmt.Errorf("probe.mode: unknown %q (want local|remote)", f.Probe.Mode)
	}
	if f.Probe.Mode == "remote" && f.Probe.Remote.URL == "" {
		return prober.ErrEmptyURL
	}
	return nil
}

// BuildProber returns the configured Prober. Safe to call with a nil receiver —
// returns the built-in local prober with default timeout. The probeTimeout
// argument is the resolved engine-level timeout (config takes precedence, CLI
// fallback, then package default), so we pass it in here rather than guessing.
func (f *File) BuildProber(probeTimeout time.Duration) prober.Prober {
	if f == nil || f.Probe.Mode == "" || f.Probe.Mode == "local" {
		return prober.NewLocal(probeTimeout)
	}
	return prober.NewRemote(
		f.Probe.Remote.URL,
		f.Probe.Remote.AuthHeader,
		f.Probe.Remote.AuthValue,
		f.Probe.Remote.Timeout,
	)
}

// ErrNotFound signals "no config path given" — a clean signal to the caller
// that it should run with pure defaults, distinct from a real read/parse
// error.
var ErrNotFound = errors.New("config: no path given")
