// Package etld computes the effective-TLD-plus-one (registrable root) for a
// domain, using the public suffix list. Thin wrapper over x/net/publicsuffix.
package etld

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Compute returns the registrable root for a domain, or the input unchanged
// when the public suffix list can't resolve a meaningful answer (IP
// literals, single-label names, entries under a private TLD we don't know).
// Domains are expected lowercased and trailing-dot-trimmed.
func Compute(domain string) string {
	if domain == "" {
		return ""
	}
	d := strings.TrimRight(strings.ToLower(strings.TrimSpace(domain)), ".")
	root, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return d
	}
	return root
}
