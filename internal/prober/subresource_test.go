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
			if got := sameOriginSubresource([]byte(c.html), "example.com", "/"); got.path != c.want {
				t.Errorf("got %q want %q", got.path, c.want)
			}
		})
	}
}

// TestSameOriginSubresource_PageBase — a relative reference resolves against
// the page it came from, which after a redirect is no longer the root.
func TestSameOriginSubresource_PageBase(t *testing.T) {
	cases := []struct{ page, src, want string }{
		{"/int/en", "assets/x.js", "/int/assets/x.js"},
		{"/int/en/", "assets/x.js", "/int/en/assets/x.js"},
		{"/int/en", "/assets/x.js", "/assets/x.js"},
		{"/int/en?x=1", "x.js", "/int/x.js"},
	}
	for _, c := range cases {
		html := `<script src="` + c.src + `"></script>`
		if got := sameOriginSubresource([]byte(html), "example.com", c.page); got.path != c.want {
			t.Errorf("page %q src %q: got %q want %q", c.page, c.src, got.path, c.want)
		}
	}
}

// TestSameOriginSubresource_Kind — the asset comes with what it is, since the
// request for a module, a classic script and a stylesheet each read differently.
func TestSameOriginSubresource_Kind(t *testing.T) {
	cases := []struct {
		name, html string
		want       fetchKind
	}{
		{"classic script", `<script src="/a.js"></script>`, fetchScript},
		{"module script", `<script type="module" src="/a.js"></script>`, fetchModule},
		{"stylesheet", `<link rel="stylesheet" href="/a.css">`, fetchStyle},
		{"module preload", `<link rel="modulepreload" href="/a.js">`, fetchModule},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sameOriginSubresource([]byte(c.html), "example.com", "/"); got.kind != c.want {
				t.Errorf("kind %d want %d", got.kind, c.want)
			}
		})
	}
}

// TestRequestsReadAsChrome — both requests must carry what a bot filter looks
// for in a browser's: a navigation that asks for a document, an asset fetch
// that names its destination and the page it came from, one Chrome release
// across the User-Agent and the client hints. And no Accept-Encoding: the
// cutoff counts bytes on the wire, and compression shrinks them below it.
func TestRequestsReadAsChrome(t *testing.T) {
	var page, bundle atomic.Pointer[http.Header]
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		h := r.Header.Clone()
		page.Store(&h)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, smallSPA)
	})
	mux.HandleFunc("/assets/index.js", func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Clone()
		bundle.Store(&h)
		w.Header().Set("Content-Type", "application/javascript")
		w.Write([]byte(strings.Repeat("a", 2*httpReadLimit)))
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	runHTTPStage(t, srv, 2*time.Second)

	pg, bn := page.Load(), bundle.Load()
	if pg == nil || bn == nil {
		t.Fatalf("page seen=%v, bundle seen=%v: both requests must reach the server", pg != nil, bn != nil)
	}
	expect := func(what string, h *http.Header, key, want string) {
		t.Helper()
		if got := h.Get(key); got != want {
			t.Errorf("%s %s = %q want %q", what, key, got, want)
		}
	}
	if !strings.HasPrefix(pg.Get("Accept"), "text/html") {
		t.Errorf("page Accept = %q: a navigation asks for a document, and Accept: */* is what draws the 403", pg.Get("Accept"))
	}
	expect("page", pg, "Sec-Fetch-Mode", "navigate")
	expect("page", pg, "Sec-Fetch-Dest", "document")
	// smallSPA loads its bundle as a module, so it is fetched in cors mode, with an Origin.
	expect("bundle", bn, "Sec-Fetch-Mode", "cors")
	expect("bundle", bn, "Sec-Fetch-Dest", "script")
	expect("bundle", bn, "Sec-Fetch-Site", "same-origin")
	expect("bundle", bn, "Origin", "https://example.com")
	expect("bundle", bn, "Referer", "https://example.com/")
	for what, h := range map[string]*http.Header{"page": pg, "bundle": bn} {
		if ae := h.Get("Accept-Encoding"); ae != "" {
			t.Errorf("%s Accept-Encoding = %q, want none", what, ae)
		}
		ua := h.Get("User-Agent")
		i := strings.Index(ua, "Chrome/")
		if i < 0 {
			t.Fatalf("%s User-Agent %q names no Chrome release", what, ua)
		}
		major, _, _ := strings.Cut(ua[i+len("Chrome/"):], ".")
		if !strings.Contains(h.Get("Sec-Ch-Ua"), `"Google Chrome";v="`+major+`"`) {
			t.Errorf("%s client hints %q name another release than User-Agent %q", what, h.Get("Sec-Ch-Ua"), ua)
		}
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
