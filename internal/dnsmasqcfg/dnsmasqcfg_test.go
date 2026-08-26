package dnsmasqcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withTempPath points Path at a temp file for the duration of a test, so the
// real Write is exercised without touching /etc/dnsmasq.d/.
func withTempPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ladon-manual.conf")
	orig := Path
	Path = p
	t.Cleanup(func() { Path = orig })
	return p
}

func TestWriteFormatAndDedup(t *testing.T) {
	path := withTempPath(t)
	changed, err := Write("ladon_manual", []string{
		"openai.com",
		"OPENAI.COM",    // case-insensitive dedup
		"openai.com.",   // trailing dot dedup
		"  openai.com ", // whitespace dedup
		"twitch.tv",
		"",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first write should report changed=true")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	if !strings.Contains(got, "ipset=/openai.com/ladon_manual") {
		t.Errorf("openai entry missing in:\n%s", got)
	}
	if !strings.Contains(got, "ipset=/twitch.tv/ladon_manual") {
		t.Errorf("twitch entry missing in:\n%s", got)
	}
	// Dedup: only ONE openai.com line.
	if strings.Count(got, "openai.com") != 1 {
		t.Errorf("expected one openai.com line, got:\n%s", got)
	}
}

func TestWriteSkipsRestartWhenUnchanged(t *testing.T) {
	withTempPath(t)
	domains := []string{"openai.com", "twitch.tv"}

	changed, err := Write("ladon_manual", domains)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first write should report changed=true")
	}

	// Identical content → no change → caller skips the dnsmasq restart.
	changed, err = Write("ladon_manual", domains)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("identical write should report changed=false")
	}

	// Different content → change again.
	changed, err = Write("ladon_manual", append(append([]string{}, domains...), "discord.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("modified write should report changed=true")
	}
}
