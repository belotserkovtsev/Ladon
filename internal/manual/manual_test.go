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
