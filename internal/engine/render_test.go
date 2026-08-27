package engine

import (
	"encoding/json"
	"strings"
	"testing"
)

// The plain list is the neutral form and stays the default: whoever reads it
// needs no schema and no agreement with anyone.
func TestRenderDomainsIsThePlainList(t *testing.T) {
	for _, format := range []string{"", "domains"} {
		got, err := renderVerdict(format, []string{"a.test", "b.test"})
		if err != nil {
			t.Fatalf("format %q: %v", format, err)
		}
		if !strings.Contains(got, "\na.test\n") || !strings.Contains(got, "\nb.test\n") {
			t.Errorf("format %q: domains missing:\n%s", format, got)
		}
		if !strings.HasPrefix(got, "#") {
			t.Errorf("format %q: no header — a reader cannot tell what this file is", format)
		}
	}
}

// sing-box reloads a local rule-set when the file changes, so the file has to
// be valid on its own: parseable, versioned, and carrying the domains.
func TestRenderSingBoxIsAValidRuleSet(t *testing.T) {
	got, err := renderVerdict("sing-box", []string{"a.test", "b.test"})
	if err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Version int `json:"version"`
		Rules   []struct {
			Domain []string `json:"domain"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, got)
	}
	if doc.Version == 0 {
		t.Error("no schema version — sing-box needs one to read the file")
	}
	if len(doc.Rules) != 1 {
		t.Fatalf("want one rule carrying the domains, got %d", len(doc.Rules))
	}
	if len(doc.Rules[0].Domain) != 2 {
		t.Errorf("domains = %v, want both", doc.Rules[0].Domain)
	}
}

// Nothing judged blocked yet is a real state, not an error, and it has to
// produce a file sing-box can still read — otherwise the client keeps acting
// on whatever it read last.
func TestRenderSingBoxWithNothingBlocked(t *testing.T) {
	got, err := renderVerdict("sing-box", nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version int               `json:"version"`
		Rules   []json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal([]byte(got), &doc); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, got)
	}
	if doc.Version == 0 {
		t.Error("no schema version")
	}
	if doc.Rules == nil {
		t.Error("rules must be present and empty, not absent")
	}
}

// A typo in the config should be caught rather than silently writing something
// no one can read.
func TestRenderRejectsAnUnknownFormat(t *testing.T) {
	if _, err := renderVerdict("xray-maybe", []string{"a.test"}); err == nil {
		t.Fatal("unknown format accepted")
	}
}
