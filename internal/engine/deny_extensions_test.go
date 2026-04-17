package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

// TestLoadDenyExtensions_UpsertsIntoManualEntries validates that each enabled
// deny preset lands in manual_entries under list_name='deny' — the same tier
// as ManualDenyPath, so the tailer skip and probe-worker filter both honor it.
func TestLoadDenyExtensions_UpsertsIntoManualEntries(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	extDir := filepath.Join(dir, "extensions")
	if err := os.Mkdir(extDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePreset(t, extDir, "ru-direct.txt", "gosuslugi.ru\nmail.ru\n# comment\n\nvk-analytics.ru\n")
	writePreset(t, extDir, "corp.txt", "internal.corp\n")

	cfg := Defaults("/dev/null")
	cfg.ExtensionsPath = extDir
	cfg.DenyExtensions = []string{"ru-direct", "corp"}

	loadDenyExtensions(ctx, s, cfg)

	wantDeny := []string{"gosuslugi.ru", "mail.ru", "vk-analytics.ru", "internal.corp"}
	for _, d := range wantDeny {
		in, err := s.IsInDenyList(ctx, d, d)
		if err != nil {
			t.Fatalf("IsInDenyList(%s): %v", d, err)
		}
		if !in {
			t.Errorf("%s not in deny list after loadDenyExtensions", d)
		}
	}
}

// TestLoadDenyExtensions_MissingFileIsSkipped verifies the loader logs and
// continues rather than aborting when a configured preset is absent — matches
// allow-extension behavior, important because an install.sh upgrade mid-boot
// shouldn't crash the engine if one preset was renamed.
func TestLoadDenyExtensions_MissingFileIsSkipped(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := storage.Open(filepath.Join(dir, "engine.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	if err := s.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	extDir := filepath.Join(dir, "extensions")
	if err := os.Mkdir(extDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writePreset(t, extDir, "present.txt", "keep.me\n")

	cfg := Defaults("/dev/null")
	cfg.ExtensionsPath = extDir
	cfg.DenyExtensions = []string{"missing", "present"}

	loadDenyExtensions(ctx, s, cfg) // must not panic

	in, err := s.IsInDenyList(ctx, "keep.me", "keep.me")
	if err != nil {
		t.Fatal(err)
	}
	if !in {
		t.Error("present preset not loaded — loader bailed on the missing one")
	}
}

func writePreset(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
