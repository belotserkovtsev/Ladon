package config

import (
	"testing"
)

func TestLoad_AllowExtensions(t *testing.T) {
	yaml := `
allow_extensions:
  - ai
  - twitch
extensions_path: /opt/ladon/extensions
`
	path := writeTemp(t, yaml)
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(f.AllowExtensions) != 2 || f.AllowExtensions[0] != "ai" || f.AllowExtensions[1] != "twitch" {
		t.Errorf("allow_extensions = %v, want [ai twitch]", f.AllowExtensions)
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
	if len(f.AllowExtensions) != 0 {
		t.Errorf("allow_extensions = %v, want empty default", f.AllowExtensions)
	}
	if f.ExtensionsPath != "" {
		t.Errorf("extensions_path = %q, want empty default", f.ExtensionsPath)
	}
}

func TestLoad_DenyExtensions(t *testing.T) {
	yaml := `
deny_extensions:
  - ru
  - corp
extensions_path: /opt/ladon/extensions
`
	path := writeTemp(t, yaml)
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(f.DenyExtensions) != 2 || f.DenyExtensions[0] != "ru" || f.DenyExtensions[1] != "corp" {
		t.Errorf("deny_extensions = %v, want [ru corp]", f.DenyExtensions)
	}
}

func TestLoad_RejectsOverlapBetweenAllowAndDeny(t *testing.T) {
	yaml := `
allow_extensions:
  - ai
  - shared
deny_extensions:
  - shared
`
	path := writeTemp(t, yaml)
	_, err := Load(path)
	if err == nil {
		t.Fatalf("Load accepted conflicting presets — want error")
	}
}
