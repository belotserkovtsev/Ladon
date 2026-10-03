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

// smallSPA is the shape that hid the cutoff: a few KB of HTML whose real
// weight is in the bundle it loads next.
const smallSPA = `<!doctype html><html><head>
<link rel="stylesheet" href="/assets/index.css">
<script type="module" crossorigin src="/assets/index.js"></script>
</head><body><div id="root"></div></body></html>`

// runHTTPStage dials the test server the way probeTCPTLS does and runs the
// HTTP stage against it.
func runHTTPStage(t *testing.T, srv *httptest.Server, timeout time.Duration) Result {
	t.Helper()
	host, port := splitHostPort(t, srv.Listener.Addr().String())
	r := Result{Domain: "example.com", ResolvedIPs: []string{host}}
	conn := probeTLSStaged(&r, host, port, 2*time.Second)
	if conn == nil {
		t.Fatalf("TLS handshake failed: %s / %s", r.FailureCode, r.FailureReason)
	}
	probeHTTPStaged(&r, conn, timeout)
	conn.Close()
	return r
}

// servePage answers the root with body under the given content type.
func servePage(mux *http.ServeMux, contentType, body string) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", contentType)
		fmt.Fprint(w, body)
	})
}

// freezeAfter sends n bytes of a response announced as much larger, then goes
// silent — the ~16 KB freeze as the client sees it.
func freezeAfter(n int, hits *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Content-Length", "200000")
		w.Write([]byte(strings.Repeat("a", n)))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}
}

// TestSubresource_CutoffBehindSmallPage — the case that motivated the stage:
// the page is complete and small, the bundle freezes midway. The site is
// broken for a browser, so the probe must not call it clear.
func TestSubresource_CutoffBehindSmallPage(t *testing.T) {
	var hits atomic.Int32
	mux := http.NewServeMux()
	servePage(mux, "text/html; charset=utf-8", smallSPA)
	mux.HandleFunc("/assets/index.js", freezeAfter(10*1024, &hits))
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	r := runHTTPStage(t, srv, 700*time.Millisecond)

	if hits.Load() != 1 {
		t.Fatalf("bundle fetched %d times, want 1 — the script must win over the stylesheet", hits.Load())
	}
	if r.HTTPOK == nil || *r.HTTPOK {
		t.Fatalf("HTTPOK=%v want ptr(false): a bundle frozen midway breaks the site (code=%q reason=%q)",
			r.HTTPOK, r.FailureCode, r.FailureReason)
	}
	if r.FailureCode != CodeHTTPTimeout {
		t.Errorf("FailureCode=%q want %q", r.FailureCode, CodeHTTPTimeout)
	}
	for _, want := range []string{"subresource /assets/index.js", "cut after 10240 bytes"} {
		if !strings.Contains(r.FailureReason, want) {
			t.Errorf("reason %q should contain %q", r.FailureReason, want)
		}
	}
}

// TestSubresource_HealthyAssetStaysClear — the bundle streams past the read
// limit, so the path carries; the verdict must stay clear.
func TestSubresource_HealthyAssetStaysClear(t *testing.T) {
	var hits atomic.Int32
	mux := http.NewServeMux()
	servePage(mux, "text/html; charset=utf-8", smallSPA)
	mux.HandleFunc("/assets/index.js", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(strings.Repeat("a", 2*httpReadLimit)))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	r := runHTTPStage(t, srv, 2*time.Second)

	if hits.Load() != 1 {
		t.Errorf("bundle fetched %d times, want 1", hits.Load())
	}
	if r.HTTPOK == nil || !*r.HTTPOK || r.FailureCode != CodeOK {
		t.Errorf("HTTPOK=%v code=%q want clear (reason=%q)", r.HTTPOK, r.FailureCode, r.FailureReason)
	}
}

// TestSubresource_NoVerdictWithoutTheSignature — anything short of "bytes
// flowed, then stopped" says nothing about the cutoff. The page did load, so
// the verdict must not move.
func TestSubresource_NoVerdictWithoutTheSignature(t *testing.T) {
	cases := []struct {
		name  string
		asset http.HandlerFunc
	}{
		{"headers never arrive", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}},
		{"asset missing", func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}},
		{"asset itself small", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "console.log(1)")
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
			mux := http.NewServeMux()
			servePage(mux, "text/html; charset=utf-8", smallSPA)
			mux.HandleFunc("/assets/index.js", c.asset)
			srv := httptest.NewTLSServer(mux)
			defer srv.Close()

			r := runHTTPStage(t, srv, 700*time.Millisecond)

			if r.HTTPOK == nil || !*r.HTTPOK || r.FailureCode != CodeOK {
				t.Errorf("HTTPOK=%v code=%q reason=%q — verdict must stay clear",
					r.HTTPOK, r.FailureCode, r.FailureReason)
			}
		})
	}
}

// TestSubresource_NotFetched — the extra request is spent only where it can
// reveal something: on small HTML with a same-origin asset.
func TestSubresource_NotFetched(t *testing.T) {
	bigPage := `<!doctype html><html><head><script src="/assets/index.js"></script></head><body>` +
		strings.Repeat("x", httpReadLimit) + `</body></html>`
	cases := []struct {
		name, contentType, page string
	}{
		{"page already fills the read limit", "text/html", bigPage},
		{"not HTML", "application/json", `{"html":"<script src=\"/assets/index.js\"></script>"}`},
		{"asset on another host", "text/html", `<html><script src="https://cdn.example.net/assets/index.js"></script></html>`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var hits atomic.Int32
			mux := http.NewServeMux()
			servePage(mux, c.contentType, c.page)
			mux.HandleFunc("/assets/index.js", freezeAfter(10*1024, &hits))
			srv := httptest.NewTLSServer(mux)
			defer srv.Close()

			r := runHTTPStage(t, srv, 700*time.Millisecond)

			if hits.Load() != 0 {
				t.Errorf("asset fetched %d times, want 0", hits.Load())
			}
			if r.HTTPOK == nil || !*r.HTTPOK {
				t.Errorf("HTTPOK=%v want ptr(true) (code=%q)", r.HTTPOK, r.FailureCode)
			}
		})
	}
}

func TestSameOriginSubresource(t *testing.T) {
	cases := []struct {
		name, html, want string
	}{
		{"script wins over stylesheet", `<link rel="stylesheet" href="/a.css"><script src="/b.js"></script>`, "/b.js"},
		{"stylesheet when no script", `<link rel="stylesheet" href="/a.css">`, "/a.css"},
		{"module preload", `<link rel="modulepreload" href="/chunk.js">`, "/chunk.js"},
		{"rel with several tokens", `<link rel="preload stylesheet" href="/a.css">`, "/a.css"},
		{"relative path", `<script src="assets/x.js"></script>`, "/assets/x.js"},
		{"query kept", `<script src="https://example.com/x.js?v=2"></script>`, "/x.js?v=2"},
		{"host compared without case", `<script src="https://EXAMPLE.com/x.js"></script>`, "/x.js"},
		{"inline script skipped", `<script>var a = 1</script><script src="/late.js"></script>`, "/late.js"},
		{"cross-origin script falls back to style", `<script src="https://cdn.example.net/x.js"></script><link rel="stylesheet" href="/s.css">`, "/s.css"},
		{"other host", `<script src="https://cdn.example.net/x.js"></script>`, ""},
		{"protocol-relative other host", `<script src="//cdn.example.net/x.js"></script>`, ""},
		{"plain http", `<script src="http://example.com/x.js"></script>`, ""},
		{"other port", `<script src="https://example.com:8443/x.js"></script>`, ""},
		{"data uri", `<script src="data:text/javascript,1"></script>`, ""},
		{"icon is not a stylesheet", `<link rel="icon" href="/favicon.ico">`, ""},
		{"the page itself", `<script src="/"></script>`, ""},
		{"nothing to fetch", `<html><body>hi</body></html>`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sameOriginSubresource([]byte(c.html), "example.com"); got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestIsHTML(t *testing.T) {
	cases := []struct {
		contentType, body string
		want              bool
	}{
		{"text/html; charset=utf-8", "", true},
		{"application/xhtml+xml", "", true},
		{"application/json", "<!doctype html><html>", false}, // the declared type wins
		{"", "<!doctype html><html><head></head></html>", true},
		{"", `{"a":1}`, false},
	}
	for _, c := range cases {
		if got := isHTML(c.contentType, []byte(c.body)); got != c.want {
			t.Errorf("isHTML(%q, %q) = %v want %v", c.contentType, c.body, got, c.want)
		}
	}
}
