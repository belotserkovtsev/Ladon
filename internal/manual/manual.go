// Package manual loads allow/deny lists from plain text files. Each non-blank,
// non-comment line is either a domain (default) or an IPv4 CIDR (detected via
// net.ParseCIDR — covers single-IP /32 too). Domains feed manual_entries +
// dnsmasq's ipset= directive; CIDRs go to a separate kernel hash:net set so
// services with DNS-bypassing data planes (Telegram MTProto, BitTorrent peer
// swarms, etc.) can still be tunneled. Loading is additive — removing a line
// from the file does NOT remove the row from the DB (operator explicitly
// clears if needed).
package manual

import (
	"bufio"
	"context"
	"log"
	"net"
	"os"
	"strings"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

// Load reads path and upserts each domain into manual_entries under listName.
// Missing or unreadable files are a no-op — callers choose whether to care.
// Returns the number of entries actually upserted.
func Load(ctx context.Context, store *storage.Store, path, listName string) (int, error) {
	if path == "" {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domain := strings.ToLower(strings.TrimRight(line, "."))
		if domain == "" {
			continue
		}
		if err := store.UpsertManual(ctx, domain, listName); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}

// Entries is the parsed contents of a list file split by line shape.
// Domains feed dnsmasq's ipset= directive (DNS-driven path); CIDRs feed a
// separate hash:net ipset (DNS-bypassing data planes).
type Entries struct {
	Domains []string
	CIDRs   []string
}

// ReadEntries parses path's lines and returns domains + CIDRs separated.
// Lines that net.ParseCIDR accepts as IPv4 (incl. plain /32-implied IPs) go
// to CIDRs; everything else is treated as a domain. IPv6 CIDRs are dropped
// with a warning — ladon's routing pipeline is v4-only today (engine ignores
// AAAA replies, ladon_engine/ladon_manual are family inet sets). A missing
// file returns empty Entries and no error so callers can call unconditionally.
func ReadEntries(path string) (Entries, error) {
	var out Entries
	if path == "" {
		return out, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// CIDR detection. ParseCIDR rejects bare IPs ("91.108.4.1") so we
		// promote those to /32 first — operators sometimes drop a single
		// host into the same file as a CIDR block, no reason to make them
		// type the suffix.
		probe := line
		if !strings.Contains(probe, "/") && net.ParseIP(probe) != nil {
			probe = probe + "/32"
		}
		if ip, ipnet, err := net.ParseCIDR(probe); err == nil {
			if ip.To4() == nil {
				log.Printf("manual: skipping IPv6 CIDR %q in %s (v6 routing not yet supported)", line, path)
				continue
			}
			out.CIDRs = append(out.CIDRs, ipnet.String())
			continue
		}
		domain := strings.ToLower(strings.TrimRight(line, "."))
		if domain == "" {
			continue
		}
		out.Domains = append(out.Domains, domain)
	}
	return out, sc.Err()
}
