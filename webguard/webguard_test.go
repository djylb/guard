package webguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
})

func mustGuard(t testing.TB, c Config) *Guard {
	t.Helper()
	g, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func request(method, host, remote string, header map[string]string) *http.Request {
	r := httptest.NewRequest(method, "http://"+host+"/admin", nil)
	r.Host = host
	r.RemoteAddr = remote
	for k, v := range header {
		r.Header.Set(k, v)
	}
	return r
}

func TestHosts(t *testing.T) {
	g := mustGuard(t, Config{Hosts: []string{"Admin.Example.com", "panel.example.com:8443", "[2001:db8::1]:9000", "2001:db8::2", "192.0.2.1"}})
	tests := []struct {
		host string
		ok   bool
	}{
		{"admin.example.com", true},
		{"ADMIN.example.COM:1234", true},
		{"admin.example.com.", true},
		{"admin.example.com.:80", true},
		{"panel.example.com:8443", true},
		{"panel.example.com", false},
		{"panel.example.com:443", false},
		{"[2001:db8::1]:9000", true},
		{"[2001:db8::1]", false},
		{"[2001:db8::2]:1", true},
		{"[2001:db8::2]", true},
		{"192.0.2.1:8080", true},
		{"192.0.2.1", true},
		{"localhost", false},
		{"127.0.0.1:8080", false},
		{"evil.example.com", false},
		{"admin.example.com.evil.com", false},
		{"", false},
		{"admin.example.com:", false},
		{"admin.example.com:99999", false},
		{"admin.example.com:80:80", false},
		{"admin.example.com:+80", false},
		{"2001:db8::2", false},
		{"[2001:db8::2%25eth0]:80", false},
		{"[2001:db8::2", false},
		{"[2001:db8::2]x", false},
		{"[192.0.2.1]:80", false},
		{"admin example.com", false},
		{"admin.example.com/x", false},
		{".", false},
	}
	for _, tt := range tests {
		if got := g.allowedHost(tt.host); got != tt.ok {
			t.Errorf("host %q: allowed %v, want %v", tt.host, got, tt.ok)
		}
	}
}

func TestLoopback(t *testing.T) {
	g := mustGuard(t, LocalAdmin())
	for host, ok := range map[string]bool{
		"localhost:8080":           true,
		"LOCALHOST":                true,
		"localhost.":               true,
		"127.0.0.1:8080":           true,
		"127.1.2.3":                true,
		"[::1]:8080":               true,
		"[::ffff:127.0.0.1]:80":    true,
		"foo.localhost":            false,
		"localhost.evil.com":       false,
		"0.0.0.0:8080":             false,
		"192.168.1.2:8080":         false,
		"[::1%25lo]:80":            false,
		"rebind.attacker.example":  false,
		"rebind.attacker.example:": false,
	} {
		if got := g.allowedHost(host); got != ok {
			t.Errorf("host %q: allowed %v, want %v", host, got, ok)
		}
	}
	for remote, ok := range map[string]bool{
		"127.0.0.1:5000":        true,
		"[::1]:5000":            true,
		"[::ffff:127.0.0.1]:80": true,
		"192.0.2.1:5000":        false,
		"@":                     false,
		"":                      false,
		"127.0.0.1":             false,
	} {
		err := g.Check(request(http.MethodGet, "localhost:8080", remote, nil))
		if (err == nil) != ok || (!ok && !errors.Is(err, ErrPeer)) {
			t.Errorf("peer %q: %v", remote, err)
		}
	}
}

func TestCrossOrigin(t *testing.T) {
	g := mustGuard(t, Config{Hosts: []string{"admin.example.com"}, TrustedOrigins: []string{"https://sso.example.com"}})
	const host = "admin.example.com"
	tests := []struct {
		header map[string]string
		method string
		ok     bool
	}{
		{nil, http.MethodGet, true},
		{map[string]string{"Sec-Fetch-Site": "cross-site"}, http.MethodGet, true},
		{map[string]string{"Sec-Fetch-Site": "cross-site"}, http.MethodPost, false},
		{map[string]string{"Sec-Fetch-Site": "same-site"}, http.MethodPost, false},
		{map[string]string{"Sec-Fetch-Site": "same-origin"}, http.MethodPost, true},
		{map[string]string{"Sec-Fetch-Site": "none"}, http.MethodPost, true},
		{map[string]string{"Origin": "https://admin.example.com"}, http.MethodPost, true},
		{map[string]string{"Origin": "https://evil.example.com"}, http.MethodPut, false},
		{map[string]string{"Origin": "null"}, http.MethodDelete, false},
		{map[string]string{"Origin": "https://sso.example.com", "Sec-Fetch-Site": "same-site"}, http.MethodPost, true},
		{nil, http.MethodPost, true}, // a non-browser client, allowed without RequireOrigin
	}
	for i, tt := range tests {
		err := g.Check(request(tt.method, host, "192.0.2.9:1", tt.header))
		if (err == nil) != tt.ok || (!tt.ok && !errors.Is(err, ErrCrossOrigin)) {
			t.Errorf("case %d (%s %v): %v", i, tt.method, tt.header, err)
		}
	}
	// DNS rebinding: the page's own name arrives as Host and Origin.
	err := g.Check(request(http.MethodPost, "rebind.example.net", "192.0.2.9:1",
		map[string]string{"Origin": "http://rebind.example.net", "Sec-Fetch-Site": "same-origin"}))
	if !errors.Is(err, ErrHost) {
		t.Fatalf("rebinding: %v", err)
	}
}

func TestRequireOrigin(t *testing.T) {
	g := mustGuard(t, Config{Hosts: []string{"localhost:8080"}, RequireOrigin: true})
	const host = "localhost:8080"
	for ref, ok := range map[string]bool{
		"":                                  false,
		"http://localhost:8080/admin/users": true,
		"https://localhost:8080/":           true,
		"http://localhost:8081/":            false,
		"http://evil.example/":              false,
		"ftp://localhost:8080/":             false,
		"%zz":                               false,
	} {
		h := map[string]string{}
		if ref != "" {
			h["Referer"] = ref
		}
		err := g.Check(request(http.MethodPost, host, "127.0.0.1:1", h))
		if (err == nil) != ok {
			t.Errorf("Referer %q: %v", ref, err)
		}
	}
	if err := g.Check(request(http.MethodGet, host, "127.0.0.1:1", nil)); err != nil {
		t.Errorf("GET without Origin: %v", err)
	}
}

func TestHandler(t *testing.T) {
	var denied error
	g := mustGuard(t, Config{
		Hosts:           []string{"localhost"},
		SecurityHeaders: true,
		Deny: func(w http.ResponseWriter, _ *http.Request, err error) {
			denied = err
			w.WriteHeader(http.StatusTeapot)
		},
	})
	h := g.Handler(okHandler)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request(http.MethodGet, "localhost", "127.0.0.1:1", nil))
	if rec.Code != http.StatusNoContent || rec.Header().Get("X-Frame-Options") != "DENY" ||
		rec.Header().Get("Content-Security-Policy") != "frame-ancestors 'none'" {
		t.Fatalf("allowed: %d %v", rec.Code, rec.Header())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, request(http.MethodGet, "evil", "127.0.0.1:1", nil))
	if rec.Code != http.StatusTeapot || !errors.Is(denied, ErrHost) {
		t.Fatalf("denied: %d %v", rec.Code, denied)
	}
	// The default deny handler.
	h = mustGuard(t, Config{Hosts: []string{"localhost"}}).Handler(okHandler)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, request(http.MethodGet, "evil", "127.0.0.1:1", nil))
	if rec.Code != http.StatusForbidden || rec.Header().Get("X-Frame-Options") != "" {
		t.Fatalf("default deny: %d %v", rec.Code, rec.Header())
	}
}

func TestConfig(t *testing.T) {
	for _, c := range []Config{
		{},
		{Hosts: []string{""}},
		{Hosts: []string{"a b"}},
		{Hosts: []string{"a:b"}},
		{Hosts: []string{"[::1"}},
		{Hosts: []string{"x"}, TrustedOrigins: []string{"not an origin"}},
	} {
		if _, err := New(c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("New(%+v) = %v", c, err)
		}
	}
}

func FuzzSplitHost(f *testing.F) {
	for _, s := range []string{"localhost:8080", "[::1]:80", "a.b.", "[::1", "::1", "x:99999", "[fe80::1%25en0]:1"} {
		f.Add(s)
	}
	g := mustGuard(f, Config{Hosts: []string{"admin.example.com", "[::1]:80"}, LoopbackHosts: true})
	f.Fuzz(func(t *testing.T, s string) {
		for _, bare := range []bool{false, true} {
			host, port, ok := splitHost(s, bare)
			if !ok {
				continue
			}
			if host == "" || (port != "" && !validPort(port)) {
				t.Fatalf("splitHost(%q) = %q, %q", s, host, port)
			}
			if !bare && !strings.Contains(s, host) {
				t.Fatalf("splitHost(%q) host %q not in input", s, host)
			}
		}
		if g.allowedHost(s) {
			host, _, _ := splitHost(s, false)
			if !loopbackHost(host) && !strings.EqualFold(host, "admin.example.com") && host != "::1" {
				t.Fatalf("allowed host %q", s)
			}
		}
	})
}

func BenchmarkCheck(b *testing.B) {
	g := mustGuard(b, LocalAdmin())
	r := request(http.MethodPost, "localhost:8080", "127.0.0.1:5000", map[string]string{"Origin": "http://localhost:8080"})
	b.ReportAllocs()
	for b.Loop() {
		if err := g.Check(r); err != nil {
			b.Fatal(err)
		}
	}
}
