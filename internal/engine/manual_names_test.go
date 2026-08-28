package engine

import (
	"testing"
	"time"
)

// The manual set is filled by eTLD+1 expansion as well as by the listed names,
// so ingest has to treat a subdomain of a listed name as worth a sync — that is
// what keeps a freshly-resolved CDN host from waiting out the safety tick.
func TestNameSetMatches(t *testing.T) {
	s := newNameSet([]string{"youtube.com", "googlevideo.com"})

	member := []string{
		"youtube.com",                       // listed verbatim
		"www.youtube.com",                   // subdomain of a listed name
		"rr1---sn-ntqe6n7r.googlevideo.com", // per-session host, same family
	}
	for _, d := range member {
		if !s.matches(d) {
			t.Errorf("matches(%q) = false, want true", d)
		}
	}

	stranger := []string{
		"example.com",
		"notyoutube.com",     // shares a suffix in text only, different eTLD+1
		"googlevideo.com.ru", // different registrable domain
		"",
	}
	for _, d := range stranger {
		if s.matches(d) {
			t.Errorf("matches(%q) = true, want false", d)
		}
	}
}

// Ingest holds a nil set whenever dnsmasq owns the manual list, and calls
// matches on it for every observation — it has to stay quiet rather than panic.
func TestNameSetNilIsNeverAMatch(t *testing.T) {
	var s *nameSet
	if s.matches("youtube.com") {
		t.Fatal("nil nameSet must not match")
	}
}

// Ingest pokes the manual syncer on every observation of a listed name, which
// on a busy resolver is a continuous stream — far more traffic than the
// hot-probe verdicts the same mechanism carries for the engine set. A pass is a
// lookup per domain plus a full reconcile, so triggered passes are spaced.
func TestTriggerDueSpacesRepeatedTriggers(t *testing.T) {
	spacing := 2 * time.Second
	last := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)

	// First trigger after a quiet spell: nothing to wait for.
	if _, ok := triggerDue(last.Add(5*time.Second), last, spacing); !ok {
		t.Error("a trigger after the window should run at once")
	}

	// A second one right behind it is deferred, not dropped, and the wait is
	// what is left of the window rather than a fresh one.
	wait, ok := triggerDue(last.Add(500*time.Millisecond), last, spacing)
	if ok {
		t.Fatal("a trigger inside the window should be deferred")
	}
	if wait != 1500*time.Millisecond {
		t.Errorf("wait = %v, want the remainder of the window (1.5s)", wait)
	}

	// Exactly at the boundary the window is over.
	if _, ok := triggerDue(last.Add(spacing), last, spacing); !ok {
		t.Error("the window should be closed once the spacing has elapsed")
	}
}
