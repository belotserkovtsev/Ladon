package prober

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// paths serves each exact path with its handler and 404s the rest.
func paths(routes map[string]http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		http.NotFound(w, r)
	})
}

// redirectTo answers with a bare redirect, the Location written as given so
// relative and absolute forms both reach the probe unaltered.
func redirectTo(loc string, code int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", loc)
		w.WriteHeader(code)
	}
}

// TestRedirect_CutoffBehindRedirect — the case that motivated following
// redirects: the landing page is a bodiless redirect, the page it leads to
// freezes midway. Whatever form the Location takes, the probe must land there
// and see the cutoff.
func TestRedirect_CutoffBehindRedirect(t *testing.T) {
	for _, loc := range []string{"/int/en", "https://example.com/int/en", "int/en"} {
		t.Run(loc, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewTLSServer(paths(map[string]http.HandlerFunc{
				"/":       redirectTo(loc, http.StatusMovedPermanently),
				"/int/en": freezeAfter(10*1024, &hits),
			}))
			defer srv.Close()

			r := runHTTPStage(t, srv, 700*time.Millisecond)

			if hits.Load() != 1 {
				t.Fatalf("target fetched %d times, want 1", hits.Load())
			}
			if r.HTTPOK == nil || *r.HTTPOK {
				t.Fatalf("HTTPOK=%v want ptr(false): the page the browser lands on freezes (code=%q reason=%q)",
					r.HTTPOK, r.FailureCode, r.FailureReason)
			}
			if r.FailureCode != CodeHTTPTimeout {
				t.Errorf("FailureCode=%q want %q", r.FailureCode, CodeHTTPTimeout)
			}
			for _, want := range []string{"redirected to /int/en", "cut after 10240 bytes"} {
				if !strings.Contains(r.FailureReason, want) {
					t.Errorf("reason %q should contain %q", r.FailureReason, want)
				}
			}
		})
	}
}

// TestRedirect_TwoHops — a cutoff one hop further down the chain is still
// within reach.
func TestRedirect_TwoHops(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(paths(map[string]http.HandlerFunc{
		"/":  redirectTo("/a", http.StatusFound),
		"/a": redirectTo("/b", http.StatusTemporaryRedirect),
		"/b": freezeAfter(10*1024, &hits),
	}))
	defer srv.Close()

	r := runHTTPStage(t, srv, 700*time.Millisecond)

	if hits.Load() != 1 || r.FailureCode != CodeHTTPTimeout {
		t.Errorf("hits=%d code=%q reason=%q, want the second hop fetched and cut",
			hits.Load(), r.FailureCode, r.FailureReason)
	}
}

// TestRedirect_HealthyTargetStaysClear — the target streams past the read
// limit, so the path carries and the verdict stays clear.
func TestRedirect_HealthyTargetStaysClear(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(paths(map[string]http.HandlerFunc{
		"/": redirectTo("https://example.com/home", http.StatusFound),
		"/home": func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(strings.Repeat("a", 2*httpReadLimit)))
		},
	}))
	defer srv.Close()

	r := runHTTPStage(t, srv, 2*time.Second)

	if hits.Load() != 1 {
		t.Errorf("target fetched %d times, want 1", hits.Load())
	}
	if r.HTTPOK == nil || !*r.HTTPOK || r.FailureCode != CodeOK {
		t.Errorf("HTTPOK=%v code=%q want clear (reason=%q)", r.HTTPOK, r.FailureCode, r.FailureReason)
	}
}

// TestRedirect_NotFollowed — only a redirect to this host over HTTPS is
// followed. Anything else points at addresses the probe does not hold, or back
// at the page it already read; a target that would freeze must never be asked.
func TestRedirect_NotFollowed(t *testing.T) {
	for _, loc := range []string{
		"https://other.example/int/en",
		"http://example.com/int/en",
		"https://example.com:8443/int/en",
		"/",
	} {
		t.Run(loc, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewTLSServer(paths(map[string]http.HandlerFunc{
				"/":       redirectTo(loc, http.StatusMovedPermanently),
				"/int/en": freezeAfter(10*1024, &hits),
			}))
			defer srv.Close()

			r := runHTTPStage(t, srv, 700*time.Millisecond)

			if hits.Load() != 0 {
				t.Errorf("target fetched %d times, want 0", hits.Load())
			}
			if r.HTTPOK == nil || !*r.HTTPOK || r.FailureCode != CodeOK {
				t.Errorf("HTTPOK=%v code=%q want clear (reason=%q)", r.HTTPOK, r.FailureCode, r.FailureReason)
			}
		})
	}
}

// TestRedirect_HopLimit — a chain longer than maxRedirects stops there, so a
// loop cannot eat the probe's time; what lies beyond is never asked.
func TestRedirect_HopLimit(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(paths(map[string]http.HandlerFunc{
		"/":  redirectTo("/a", http.StatusFound),
		"/a": redirectTo("/b", http.StatusFound),
		"/b": redirectTo("/c", http.StatusFound),
		"/c": freezeAfter(10*1024, &hits),
	}))
	defer srv.Close()

	r := runHTTPStage(t, srv, 700*time.Millisecond)

	if hits.Load() != 0 {
		t.Errorf("/c fetched %d times, want 0 — it lies past maxRedirects=%d", hits.Load(), maxRedirects)
	}
	if r.HTTPOK == nil || !*r.HTTPOK || r.FailureCode != CodeOK {
		t.Errorf("HTTPOK=%v code=%q want clear", r.HTTPOK, r.FailureCode)
	}
}

// TestRedirect_NoVerdictWithoutTheSignature — anything short of "bytes flowed,
// then stopped" on the target says nothing about the cutoff, so the verdict
// must not move.
func TestRedirect_NoVerdictWithoutTheSignature(t *testing.T) {
	cases := []struct {
		name   string
		target http.HandlerFunc
	}{
		{"headers never arrive", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}},
		{"target missing", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}},
		{"target itself small", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "hello")
		}},
		{"announced but nothing sent", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", "200000")
			w.WriteHeader(http.StatusOK)
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(paths(map[string]http.HandlerFunc{
				"/":       redirectTo("/int/en", http.StatusMovedPermanently),
				"/int/en": c.target,
			}))
			defer srv.Close()

			r := runHTTPStage(t, srv, 700*time.Millisecond)

			if r.HTTPOK == nil || !*r.HTTPOK || r.FailureCode != CodeOK {
				t.Errorf("HTTPOK=%v code=%q reason=%q — verdict must stay clear",
					r.HTTPOK, r.FailureCode, r.FailureReason)
			}
		})
	}
}

// TestRedirect_SmallTargetGetsAssetCheck — the page a redirect lands on is the
// page; when it is small HTML its asset is checked, resolved against the
// target's own path rather than the root.
func TestRedirect_SmallTargetGetsAssetCheck(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(paths(map[string]http.HandlerFunc{
		"/": redirectTo("/int/en", http.StatusMovedPermanently),
		"/int/en": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><head><script src="assets/app.js"></script></head></html>`)
		},
		"/int/assets/app.js": freezeAfter(10*1024, &hits),
	}))
	defer srv.Close()

	r := runHTTPStage(t, srv, 700*time.Millisecond)

	if hits.Load() != 1 {
		t.Fatalf("asset fetched %d times, want 1", hits.Load())
	}
	if r.FailureCode != CodeHTTPTimeout || !strings.Contains(r.FailureReason, "subresource /int/assets/app.js") {
		t.Errorf("code=%q reason=%q, want the asset behind the redirect cut", r.FailureCode, r.FailureReason)
	}
}
