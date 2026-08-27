package engine

import "testing"

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
