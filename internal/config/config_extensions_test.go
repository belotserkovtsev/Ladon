package config

import (
	"testing"
)

func TestLoad_Extensions(t *testing.T) {
	yaml := `
extensions:
  - ai
  - twitch
extensions_path: /opt/ladon/extensions
`
	path := writeTemp(t, yaml)
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(f.Extensions) != 2 || f.Extensions[0] != "ai" || f.Extensions[1] != "twitch" {
		t.Errorf("extensions = %v, want [ai twitch]", f.Extensions)
	}
	if f.ExtensionsPath != "/opt/ladon/extensions" {
		t.Errorf("extensions_path = %q", f.ExtensionsPath)
	}
}

func TestLoad_ExtensionsDefaultsAreEmpty(t *testing.T) {
	path := writeTemp(t, "---\n")
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(f.Extensions) != 0 {
		t.Errorf("extensions = %v, want empty default", f.Extensions)
	}
	if f.ExtensionsPath != "" {
		t.Errorf("extensions_path = %q, want empty default", f.ExtensionsPath)
	}
}
