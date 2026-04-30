package manual

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/belotserkovtsev/ladon/internal/storage"
)

func newStore(t *testing.T) *storage.Store {
	t.Helper()
	s, err := storage.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if err := s.Init(context.Background()); err != nil {
		t.Fatalf("init: %v", err)
	}
	return s
}

func writeFile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadParsesCommentsAndBlankLines(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	body := `# header comment
example.com

# inline group header
Facebook.COM
trailing-dot.test.

   indented.test
# another comment
`
	path := writeFile(t, body)
	n, err := Load(ctx, s, path, "allow")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if n != 4 {
		t.Fatalf("want 4 loaded, got %d", n)
	}

	got, err := s.ListManualByList(ctx, "allow")
	if err != nil {
		t.Fatal(err)
	}
	// File order: example.com, Facebook.COM → facebook.com, trailing-dot.test. → trailing-dot.test, indented.test
	// ListManualByList sorts alphabetically.
	want := []string{"example.com", "facebook.com", "indented.test", "trailing-dot.test"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("entry %d: want %q, got %q", i, w, got[i])
		}
	}
}

func TestLoadMissingFileIsNoop(t *testing.T) {
	s := newStore(t)
	n, err := Load(context.Background(), s, "/does/not/exist", "allow")
	if err != nil {
		t.Fatalf("expected no error on missing file, got %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 loaded, got %d", n)
	}
}

func TestLoadEmptyPathIsNoop(t *testing.T) {
	s := newStore(t)
	n, err := Load(context.Background(), s, "", "allow")
	if err != nil {
		t.Fatalf("expected no error on empty path, got %v", err)
	}
	if n != 0 {
		t.Fatalf("expected 0 loaded, got %d", n)
	}
}

func TestReadEntriesSplitsDomainsAndCIDRs(t *testing.T) {
	body := `# header
example.com
# Telegram DC
91.108.4.0/22
91.108.56.0/22
sub.example.com
185.76.151.42
2001:67c:4e8::/48
trailing-dot.test.

   indented.test
`
	path := writeFile(t, body)
	got, err := ReadEntries(path)
	if err != nil {
		t.Fatalf("ReadEntries: %v", err)
	}
	wantDomains := []string{"example.com", "sub.example.com", "trailing-dot.test", "indented.test"}
	if len(got.Domains) != len(wantDomains) {
		t.Fatalf("domains: want %v, got %v", wantDomains, got.Domains)
	}
	for i, w := range wantDomains {
		if got.Domains[i] != w {
			t.Errorf("domain %d: want %q, got %q", i, w, got.Domains[i])
		}
	}
	wantCIDRs := []string{"91.108.4.0/22", "91.108.56.0/22", "185.76.151.42/32"}
	if len(got.CIDRs) != len(wantCIDRs) {
		t.Fatalf("cidrs: want %v, got %v", wantCIDRs, got.CIDRs)
	}
	for i, w := range wantCIDRs {
		if got.CIDRs[i] != w {
			t.Errorf("cidr %d: want %q, got %q", i, w, got.CIDRs[i])
		}
	}
}

func TestReadEntriesMissingFileIsNoop(t *testing.T) {
	got, err := ReadEntries("/does/not/exist")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(got.Domains) != 0 || len(got.CIDRs) != 0 {
		t.Fatalf("expected empty, got %+v", got)
	}
}
