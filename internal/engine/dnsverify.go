package engine

// Resolver refusal checks.
//
// The engine judges by transport: it connects to a name and looks at what gets
// in the way. A name the resolver answered "no such name" for never reaches
// transport — there is nothing to connect to. A block of that kind is invisible
// to the probe path, and a whole class of sites is closed exactly this way: a
// resolver on the path answers NXDOMAIN for a live name, and the query vanishes
// before it starts.
//
// Poisoning is told apart from a name that really does not exist by a second
// opinion: ask for the same name over HTTPS, where a middlebox on the path
// cannot interfere. If the answers disagree, that is evidence, and conclusive:
// there is nothing left to probe, the verdict is already in.
//
// The engine leaves its own resolver alone while doing this: the service is
// addressed by number, so reaching it does not go through the resolver being
// watched, and no loop forms.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/belotserkovtsev/ladon/internal/storage"
	"github.com/belotserkovtsev/ladon/internal/watcher"
)

// DNSVerifyConfig controls the second opinion on resolver refusals.
type DNSVerifyConfig struct {
	// Enabled turns the check on. Off by default: it reaches out to a
	// third-party resolver, and that is the operator's decision, not ours.
	Enabled bool

	// URL is a DoH service answering in application/dns-json. Give it as an
	// address, not a name: otherwise its own lookup goes through the very
	// resolver whose answers are being checked.
	URL string

	// Timeout bounds a single request.
	Timeout time.Duration
}

// DNSVerifyDefaults is what the check uses when it is turned on without
// further detail.
func DNSVerifyDefaults() DNSVerifyConfig {
	return DNSVerifyConfig{
		Enabled: false,
		URL:     "https://1.1.1.1/dns-query",
		Timeout: 6 * time.Second,
	}
}

// dnsVerifier asks for a second opinion on a refusal.
type dnsVerifier struct {
	cfg    DNSVerifyConfig
	client *http.Client
}

func newDNSVerifier(cfg DNSVerifyConfig) *dnsVerifier {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 6 * time.Second
	}
	if cfg.URL == "" {
		cfg.URL = DNSVerifyDefaults().URL
	}
	return &dnsVerifier{cfg: cfg, client: &http.Client{Timeout: cfg.Timeout}}
}

// poisoned reports whether the name is alive over the encrypted path, and which
// addresses it answers with. A failed request is not evidence: the network may
// simply not have let it through, and calling that a block would be convicting
// on silence.
func (v *dnsVerifier) poisoned(ctx context.Context, domain string) (ips []string, ok bool) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		v.cfg.URL+"?name="+url.QueryEscape(domain)+"&type=A", nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("accept", "application/dns-json")

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	var body struct {
		Status int `json:"Status"`
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, false
	}
	if body.Status != 0 {
		return nil, false // no such name over the encrypted path either: an honest refusal
	}
	for _, a := range body.Answer {
		if a.Type != 1 {
			continue
		}
		ip := strings.TrimSpace(a.Data)
		// Only addresses the engine can divert count: an answer with nothing
		// but v6 leaves nothing to route, and so proves nothing here.
		if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
			continue
		}
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, false
	}
	return ips, true
}

// dnsPoisonReason is what goes into hot_entries as the reason.
func dnsPoisonReason(ips []string) string {
	return fmt.Sprintf("dns_poison: resolver denied the name, encrypted lookup returned %s",
		strings.Join(ips, ", "))
}

// verifyDenial settles a refusal: if the name is alive over the encrypted path,
// a resolver on the path substituted the answer, and that is a block — a final
// one, since there is nothing here to probe.
//
// The addresses from the encrypted answer go into dns_cache: without them
// address-based routing would get nothing, and they are the only way to reach
// a name the ordinary resolver refuses.
func verifyDenial(ctx context.Context, store *storage.Store, cfg Config, v *dnsVerifier,
	domain string, ipsetTrigger chan<- struct{}) {

	ips, poisoned := v.poisoned(ctx, domain)
	if !poisoned {
		return // an honest refusal, or the check did not get through: silence is no evidence
	}

	for _, ip := range ips {
		if err := store.UpsertDNSObservation(ctx, domain, ip, time.Time{}); err != nil {
			logIngest.Error("dns_cache upsert failed", "domain", domain, "ip", ip, "err", err)
		}
	}
	if _, err := watcher.Ingest(ctx, store, watcher.Event{Domain: domain, Peer: dnsVerifyPeer}); err != nil {
		logIngest.Error("ingest failed", "domain", domain, "err", err)
		return
	}
	cooldown := time.Now().UTC().Add(cfg.ProbeCooldown)
	if err := store.SetDomainState(ctx, domain, "hot", cooldown); err != nil {
		logIngest.Error("set state hot failed", "domain", domain, "err", err)
		return
	}
	if err := store.UpsertHotEntry(ctx, domain,
		dnsPoisonReason(ips), time.Now().UTC().Add(cfg.HotTTL)); err != nil {
		logIngest.Error("upsert hot failed", "domain", domain, "err", err)
		return
	}
	logIngest.Info("resolver denied a live name → hot", "domain", domain,
		"failure_code", "dns_poison", "addresses", strings.Join(ips, ","))
	select {
	case ipsetTrigger <- struct{}{}:
	default:
	}
}

// dnsVerifyPeer marks observations produced by the check rather than by a client.
const dnsVerifyPeer = "dns-verify"
