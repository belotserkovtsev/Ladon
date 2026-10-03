package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// dohStub is a DoH service that answers with the given body.
func dohStub(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("name"); got == "" {
			t.Errorf("request without a name: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/dns-json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

func verifierFor(url string) *dnsVerifier {
	return newDNSVerifier(DNSVerifyConfig{Enabled: true, URL: url, Timeout: 3 * time.Second})
}

// Alive over the encrypted path, refused by the ordinary resolver: substitution.
func TestPoisonedWhenEncryptedResolves(t *testing.T) {
	srv := dohStub(t, 200, `{"Status":0,"Answer":[{"type":1,"data":"93.184.216.34"}]}`)
	defer srv.Close()

	ips, poisoned := verifierFor(srv.URL).poisoned(context.Background(), "example.com")
	if !poisoned {
		t.Fatal("a name alive over DoH must count as substituted")
	}
	if len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Fatalf("wrong addresses: %v", ips)
	}
}

// No such name over the encrypted path either: the refusal is honest.
func TestNotPoisonedWhenEncryptedAlsoDenies(t *testing.T) {
	srv := dohStub(t, 200, `{"Status":3}`)
	defer srv.Close()

	if _, poisoned := verifierFor(srv.URL).poisoned(context.Background(), "nx.invalid"); poisoned {
		t.Fatal("NXDOMAIN on both paths is not a substitution")
	}
}

// An answer without addresses (only CNAME or AAAA) is no evidence: there is
// nothing to divert, and calling it a block would be judging by an empty answer.
func TestNotPoisonedWithoutAddresses(t *testing.T) {
	srv := dohStub(t, 200, `{"Status":0,"Answer":[{"type":5,"data":"other.example.com"}]}`)
	defer srv.Close()

	if _, poisoned := verifierFor(srv.URL).poisoned(context.Background(), "cname.example.com"); poisoned {
		t.Fatal("an answer without A records must not count as substitution")
	}
}

// Silence is no evidence: an unreachable check service must not turn every
// refusal into a block. That is exactly how false verdicts arrive in batches.
func TestNotPoisonedWhenVerifierUnreachable(t *testing.T) {
	srv := dohStub(t, 500, `nope`)
	srv.Close() // closed up front, so the request cannot get through

	if _, poisoned := verifierFor(srv.URL).poisoned(context.Background(), "example.com"); poisoned {
		t.Fatal("an unreachable check service must not produce a verdict")
	}
}

// A service answering with something else is no evidence either.
func TestNotPoisonedOnBadStatus(t *testing.T) {
	srv := dohStub(t, 503, `{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}`)
	defer srv.Close()

	if _, poisoned := verifierFor(srv.URL).poisoned(context.Background(), "example.com"); poisoned {
		t.Fatal("a 503 must not be taken for an answer")
	}
}

// The reason must name the addresses: whoever reads hot_entries sees what
// the name really resolves to and can check the conclusion themselves.
func TestPoisonReasonNamesAddresses(t *testing.T) {
	got := dnsPoisonReason([]string{"1.2.3.4", "5.6.7.8"})
	for _, want := range []string{"dns_poison", "1.2.3.4", "5.6.7.8"} {
		if !contains(got, want) {
			t.Fatalf("reason lacks %q: %s", want, got)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// A verdict on the name must not be undone by a probe of the address: the
// address is alive, but whoever asks the ordinary resolver still cannot reach it.
func TestPoisonReasonIsRecognisedAsNameLevel(t *testing.T) {
	reason := dnsPoisonReason([]string{"104.21.95.93"})
	if !strings.HasPrefix(reason, "dns_poison") {
		t.Fatalf("reason must start with dns_poison, or the guard against clearing it does not fire: %s", reason)
	}
}
