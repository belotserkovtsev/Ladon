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

	// AllowExtensions are bundled allow-list presets enabled by name. Each
	// name resolves to <ExtensionsPath>/<name>.txt and is loaded with the
	// same parser as ManualAllow.
	AllowExtensions []string `yaml:"allow_extensions"`
	ExtensionsPath  string   `yaml:"extensions_path"`

	// DenyExtensions are bundled deny-list presets. Shares ExtensionsPath
	// with AllowExtensions — the same file pool, just a different intent.
	// Each preset resolves to <ExtensionsPath>/<name>.txt and is loaded
	// with the same parser as ManualDeny (into manual_entries with
	// list_name='deny').
	DenyExtensions []string `yaml:"deny_extensions"`
}

// ProbeSection covers both the shared probe tuning and the backend selector.
//
// Modes:
//   - "local" (default): only the gateway-side TCP+TLS probe runs. What
//     ladon shipped with from v0.1.0 onward.
//   - "exit-compare": the gateway-side probe still runs as the baseline (and
//     remains the inline fast-path), and an additional remote HTTP probe
//     validates Hot verdicts. local FAIL + remote OK = real DPI block;
//     local FAIL + remote FAIL = methodological FP, suppressed.
type ProbeSection struct {
	Mode        string        `yaml:"mode"` // "local" (default) | "exit-compare"
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
	EngineName string        `yaml:"engine_name"` // engine-managed (default ladon_engine)
	ManualName string        `yaml:"manual_name"` // dnsmasq-managed (default ladon_manual; "" disables)
	Interval   time.Duration `yaml:"interval"`
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
	case "", "local", "exit-compare":
		// ok
	default:
		return fmt.Errorf("probe.mode: unknown %q (want local|exit-compare)", f.Probe.Mode)
	}
	if f.Probe.Mode == "exit-compare" && f.Probe.Remote.URL == "" {
		return prober.ErrEmptyURL
	}
	// A preset listed on both sides would load the same file into both
	// manual_entries tiers — operator confusion, not a useful intent.
	for _, a := range f.AllowExtensions {
		for _, d := range f.DenyExtensions {
			if a == d {
				return fmt.Errorf("extension %q listed in both allow_extensions and deny_extensions", a)
			}
		}
	}
	return nil
}

// BuildLocalProber returns the always-on local backend used by the inline
// fast-path and as the batch worker baseline. Safe to call on a nil receiver.
func (f *File) BuildLocalProber(probeTimeout time.Duration) prober.Prober {
	return prober.NewLocal(probeTimeout)
}

// BuildRemoteProber returns the optional exit-compare validator, or nil when
// remote isn't configured. The engine treats nil as "no exit-compare, just use
// the local result" — so callers don't need to check the mode separately.
func (f *File) BuildRemoteProber() prober.Prober {
	if f == nil || f.Probe.Mode != "exit-compare" {
		return nil
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
