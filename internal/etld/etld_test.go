package etld

import "testing"

func TestCompute(t *testing.T) {
	cases := map[string]string{
		"api.t-bank-app.ru":                     "t-bank-app.ru",
		"as.t-bank-app.ru":                      "t-bank-app.ru",
		"scontent-fra5-2.cdninstagram.com":      "cdninstagram.com",
		"i-fallback.instagram.com":              "instagram.com",
		"www.instagram.com":                     "instagram.com",
		"mobileproxy.passport.yandex.fi":        "yandex.fi",
		"e28622.a.akamaiedge.net":               "a.akamaiedge.net", // akamaiedge.net is a public suffix → eTLD+1 is a.akamaiedge.net
		"foo.bar.co.uk":                         "bar.co.uk",
		"example.com":                           "example.com",
		"":                                      "",
		"LOCALHOST":                             "localhost", // degrades gracefully
	}
	for in, want := range cases {
		if got := Compute(in); got != want {
			t.Errorf("Compute(%q) = %q; want %q", in, got, want)
		}
	}
}
