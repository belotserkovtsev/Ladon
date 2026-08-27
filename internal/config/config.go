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
	"strconv"
	"strings"
	"time"

	"github.com/belotserkovtsev/ladon/internal/prober"
	"gopkg.in/yaml.v3"
)

// Duration is a config duration that also understands a leading day unit ("7d"
// = 168h, "1d12h" = 36h), which the OPNsense GUI offers but Go's stdlib
// time.ParseDuration rejects. Plain ms/s/m/h still work, and a bare integer is
// read as nanoseconds. Without this, a perfectly valid GUI value like "7d" would
// crash the daemon on startup.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Tag == "!!int" {
		var ns int64
		if err := n.Decode(&ns); err != nil {
			return err
		}
		*d = Duration(ns)
		return nil
	}
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	if s == "" {
		*d = 0
		return nil
	}
	parsed, err := parseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// parseDuration extends time.ParseDuration with a leading "<int>d" day unit.
// "7d" -> 168h, "1d12h" -> 36h; anything after the day part is handed to the
// stdlib parser unchanged.
func parseDuration(s string) (time.Duration, error) {
	var days time.Duration
	if i := strings.IndexByte(s, 'd'); i > 0 {
		if n, err := strconv.Atoi(s[:i]); err == nil {
			days = time.Duration(n) * 24 * time.Hour
			s = s[i+1:]
		}
	}
	if s == "" {
		return days, nil
	}
	rest, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	return days + rest, nil
}

// File mirrors the on-disk YAML shape. All fields are optional — unset values
// fall through to the engine defaults.
type File struct {
	DB          string `yaml:"db"`
	Logfile     string `yaml:"logfile"`
	ManualAllow string `yaml:"manual_allow"`
	ManualDeny  string `yaml:"manual_deny"`

	Probe      ProbeSection      `yaml:"probe"`
	Scorer     ScorerSection     `yaml:"scorer"`
	Revalidate RevalidateSection `yaml:"revalidate"`
	Publish    PublishSection    `yaml:"publish"`
	Ipset      IpsetSection      `yaml:"ipset"`
	Log        LogSection        `yaml:"log"`

	HotTTL                 Duration `yaml:"hot_ttl"`
	DNSFreshness           Duration `yaml:"dns_freshness"`
	IgnorePeer             string   `yaml:"ignore_peer"`
	FamilyConfirmThreshold int      `yaml:"family_confirm_threshold"`

	// ManageDNSMasq: let ladon write dnsmasq's snippet and restart it. Default
	// true. A pointer so an unset key keeps the default instead of forcing
	// false. Set it to false where ladon can't drive dnsmasq — in a container,
	// or when someone else owns the resolver — and the engine fills the manual
	// set itself.
	ManageDNSMasq *bool `yaml:"manage_dnsmasq"`

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
	Mode        string   `yaml:"mode"` // "local" (default) | "exit-compare"
	Timeout     Duration `yaml:"timeout"`
	Cooldown    Duration `yaml:"cooldown"`
	Concurrency int      `yaml:"concurrency"`
	Interval    Duration `yaml:"interval"`
	Batch       int      `yaml:"batch"`

	Remote RemoteSection `yaml:"remote"`
}

// RemoteSection configures the RemoteProber. Only consulted when mode=remote.
type RemoteSection struct {
	URL        string   `yaml:"url"`
	Timeout    Duration `yaml:"timeout"`
	AuthHeader string   `yaml:"auth_header"`
	AuthValue  string   `yaml:"auth_value"`
}

// PublishSection writes out what ladon judges blocked, for tools that enforce
// differently than the kernel sets do — a proxy client routing by domain, an
// in-place bypass rewriting packets where they are. Empty path leaves it off.
type PublishSection struct {
	Path string `yaml:"path"`
	// "domains" (default) writes the plain list — no schema, no dependency on
	// anyone's format. "sing-box" writes a rule-set that client reloads on its
	// own when the file changes.
	Format   string   `yaml:"format"`
	Interval Duration `yaml:"interval"`
}

// ScorerSection mirrors scorer.Config.
type ScorerSection struct {
	Interval         Duration `yaml:"interval"`
	Window           Duration `yaml:"window"`
	PromoteThreshold int      `yaml:"promote_threshold"`
}

// RevalidateSection mirrors engine.RevalidateConfig — Phase-7 re-probing of
// terminal-state domains (cache/ignore). Disabled by default. Enabled is a
// pointer so an unset value keeps the engine default (off) rather than forcing
// false.
type RevalidateSection struct {
	Enabled  *bool    `yaml:"enabled"`
	Interval Duration `yaml:"interval"`
	Batch    int      `yaml:"batch"`
	Streak   int      `yaml:"streak"`
}

// IpsetSection mirrors the ipset knobs.
type IpsetSection struct {
	EngineName string   `yaml:"engine_name"` // engine-managed (default ladon_engine)
	ManualName string   `yaml:"manual_name"` // dnsmasq-managed (default ladon_manual; "" disables)
	CIDRName   string   `yaml:"cidr_name"`   // CIDR hash:net set fed by extensions (default ladon_cidr; "" disables)
	Interval   Duration `yaml:"interval"`
}

// LogSection tunes the daemon's structured logging. All fields are optional —
// the zero value (level=info, format=text) is the production default. journald
// rendering (priority prefix + no timestamp) is auto-detected at runtime from
// the JOURNAL_STREAM env var, so operators never set it by hand.
type LogSection struct {
	Level  string `yaml:"level"`  // debug|info|warn|error (default info)
	Format string `yaml:"format"` // text|json (default text)
	Source bool   `yaml:"source"` // include source file:line (default false)
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
	switch f.Publish.Format {
	case "", "domains", "sing-box":
		// ok
	default:
		return fmt.Errorf("publish.format: unknown %q (want domains|sing-box)", f.Publish.Format)
	}
	if f.Probe.Mode == "exit-compare" && f.Probe.Remote.URL == "" {
		return prober.ErrEmptyURL
	}
	switch f.Log.Level {
	case "", "debug", "info", "warn", "warning", "error", "err":
		// ok
	default:
		return fmt.Errorf("log.level: unknown %q (want debug|info|warn|error)", f.Log.Level)
	}
	switch f.Log.Format {
	case "", "text", "json":
		// ok
	default:
		return fmt.Errorf("log.format: unknown %q (want text|json)", f.Log.Format)
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
		time.Duration(f.Probe.Remote.Timeout),
	)
}

// ErrNotFound signals "no config path given" — a clean signal to the caller
// that it should run with pure defaults, distinct from a real read/parse
// error.
var ErrNotFound = errors.New("config: no path given")
