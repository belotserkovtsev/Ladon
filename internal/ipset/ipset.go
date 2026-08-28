// Package ipset keeps a single named address set in sync with a desired list.
//
// The set primitive differs by OS, hidden behind `backend`: Linux uses the
// `ipset` CLI, FreeBSD/OPNsense uses pf tables via `pfctl`. Rule volume is tiny
// (hundreds of IPs), so exec-ing the CLI is fine and avoids netlink/ioctl
// cross-compile pain. New() picks the backend by GOOS.
package ipset

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// backend is the per-OS set primitive operating on a named set.
type backend interface {
	exists(ctx context.Context, name string) (bool, error)
	members(ctx context.Context, name string) ([]string, error)
	add(ctx context.Context, name, ip string) error
	del(ctx context.Context, name, ip string) error
	save(ctx context.Context, name string) ([]byte, error)
}

// Manager operates on a single named set via the host's backend.
type Manager struct {
	Name string
	be   backend
}

// New returns a manager for an existing set. It does NOT create the set —
// that's an operator concern (ipset create / pf table in the ruleset) so the
// engine never mutates set schema.
func New(name string) *Manager {
	return &Manager{Name: name, be: defaultBackend()}
}

// defaultBackend picks the set primitive for the host: pf tables on FreeBSD
// (OPNsense), ipset elsewhere.
func defaultBackend() backend {
	if runtime.GOOS == "freebsd" {
		return pfctlBackend{}
	}
	return ipsetBackend{}
}

// Exists reports whether the set is actually present on the system.
func (m *Manager) Exists(ctx context.Context) (bool, error) { return m.be.exists(ctx, m.Name) }

// Members returns the current entries in the set.
func (m *Manager) Members(ctx context.Context) ([]string, error) { return m.be.members(ctx, m.Name) }

// Add inserts ip into the set (idempotent).
func (m *Manager) Add(ctx context.Context, ip string) error { return m.be.add(ctx, m.Name, ip) }

// Del removes ip from the set (idempotent).
func (m *Manager) Del(ctx context.Context, ip string) error { return m.be.del(ctx, m.Name, ip) }

// Save persists the set so a boot-time restore can repopulate it. The caller
// decides where the bytes land. On pf this is a no-op (kernel-resident).
func (m *Manager) Save(ctx context.Context) ([]byte, error) { return m.be.save(ctx, m.Name) }

// Reconcile makes the set contain exactly desired (and nothing more).
// Returns counts of adds and deletes applied. Backend-agnostic set diff.
//
// The diff is taken on a canonical key rather than the raw string, because a
// set does not always report an entry back the way it was written: a single
// host given as "10.0.0.1/32" comes back as "10.0.0.1". Diffing raw strings
// treats those as two different entries, so every pass adds the one and then
// deletes the other — the same address, leaving the set short by exactly the
// entries an operator pinned as /32. Add and Del still get the original
// strings, so each backend receives the syntax it was given.
func (m *Manager) Reconcile(ctx context.Context, desired []string) (added, removed int, err error) {
	current, err := m.Members(ctx)
	if err != nil {
		return 0, 0, err
	}
	want := make(map[string]string, len(desired))
	for _, ip := range desired {
		want[canonical(ip)] = ip
	}
	have := make(map[string]string, len(current))
	for _, ip := range current {
		have[canonical(ip)] = ip
	}

	for key, ip := range want {
		if _, ok := have[key]; ok {
			continue
		}
		if err := m.Add(ctx, ip); err != nil {
			return added, removed, err
		}
		added++
	}
	for key, ip := range have {
		if _, ok := want[key]; ok {
			continue
		}
		if err := m.Del(ctx, ip); err != nil {
			return added, removed, err
		}
		removed++
	}
	return added, removed, nil
}

// canonical renders an entry the way a set reports it back, so a desired entry
// and the member it produced compare equal. A full-length prefix is dropped
// ("10.0.0.1/32" -> "10.0.0.1"), a network is reduced to its base address
// ("10.0.0.5/24" -> "10.0.0.0/24"), and anything unparseable is returned
// untouched so an unfamiliar syntax still diffs against itself.
func canonical(entry string) string {
	if ip := net.ParseIP(entry); ip != nil {
		return ip.String()
	}
	if ip, ipnet, err := net.ParseCIDR(entry); err == nil {
		if ones, bits := ipnet.Mask.Size(); ones == bits {
			return ip.String()
		}
		return ipnet.String()
	}
	return entry
}

// ---- Linux: ipset CLI ----

type ipsetBackend struct{}

func (ipsetBackend) exists(ctx context.Context, name string) (bool, error) {
	cmd := exec.CommandContext(ctx, "ipset", "list", "-n", name)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (ipsetBackend) members(ctx context.Context, name string) ([]string, error) {
	out, err := exec.CommandContext(ctx, "ipset", "list", name).Output()
	if err != nil {
		return nil, fmt.Errorf("ipset list %s: %w", name, err)
	}
	var ips []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	inMembers := false
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Members:") {
			inMembers = true
			continue
		}
		if !inMembers || line == "" {
			continue
		}
		// Member line may be "<ip>" or "<ip> timeout N" — take the first field.
		ips = append(ips, strings.Fields(line)[0])
	}
	return ips, sc.Err()
}

func (ipsetBackend) add(ctx context.Context, name, ip string) error {
	if err := exec.CommandContext(ctx, "ipset", "add", "-exist", name, ip).Run(); err != nil {
		return fmt.Errorf("ipset add %s %s: %w", name, ip, err)
	}
	return nil
}

func (ipsetBackend) del(ctx context.Context, name, ip string) error {
	if err := exec.CommandContext(ctx, "ipset", "del", "-exist", name, ip).Run(); err != nil {
		return fmt.Errorf("ipset del %s %s: %w", name, ip, err)
	}
	return nil
}

func (ipsetBackend) save(ctx context.Context, name string) ([]byte, error) {
	return exec.CommandContext(ctx, "ipset", "save", name).Output()
}

// ---- FreeBSD/OPNsense: pf tables via pfctl ----

type pfctlBackend struct{}

func (pfctlBackend) exists(ctx context.Context, name string) (bool, error) {
	// `pfctl -t <name> -T show` exits non-zero ("Table does not exist") when
	// the table is absent; zero (possibly empty output) when it exists.
	if err := exec.CommandContext(ctx, "pfctl", "-t", name, "-T", "show").Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (pfctlBackend) members(ctx context.Context, name string) ([]string, error) {
	out, err := exec.CommandContext(ctx, "pfctl", "-t", name, "-T", "show").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, nil // table absent (or empty/GC'd) → treat as no members
		}
		return nil, fmt.Errorf("pfctl -T show %s: %w", name, err)
	}
	var ips []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		ips = append(ips, line)
	}
	return ips, sc.Err()
}

func (pfctlBackend) add(ctx context.Context, name, ip string) error {
	if err := exec.CommandContext(ctx, "pfctl", "-t", name, "-T", "add", ip).Run(); err != nil {
		return fmt.Errorf("pfctl -T add %s %s: %w", name, ip, err)
	}
	return nil
}

func (pfctlBackend) del(ctx context.Context, name, ip string) error {
	if err := exec.CommandContext(ctx, "pfctl", "-t", name, "-T", "delete", ip).Run(); err != nil {
		return fmt.Errorf("pfctl -T delete %s %s: %w", name, ip, err)
	}
	return nil
}

func (pfctlBackend) save(ctx context.Context, name string) ([]byte, error) {
	// pf tables are kernel-resident; persistence is the operator's (pf ruleset
	// or OPNsense alias), not ours.
	return nil, nil
}
