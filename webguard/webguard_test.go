package webguard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	iaddr "github.com/djylb/guard/internal/addr"
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
		"127.0.0.1":             true, // as set by tests and custom servers
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

func TestClientAddr(t *testing.T) {
	g := mustGuard(t, Config{Hosts: []string{"admin.example.com"}, TrustedProxies: []string{"10.0.0.0/8", "::1"}})
	tests := []struct {
		remote string
		xff    []string
		want   string // "" for an error
	}{
		{remote: "192.0.2.1:5000", want: "192.0.2.1"},
		// An untrusted peer's header is ignored.
		{remote: "192.0.2.1:5000", xff: []string{"198.51.100.1"}, want: "192.0.2.1"},
		// A trusted proxy that names no client fails closed: its own
		// address is never the client's.
		{remote: "10.0.0.1:5000"},
		{remote: "10.0.0.1:5000", xff: []string{"198.51.100.1"}, want: "198.51.100.1"},
		// The right-most address that is not a trusted proxy wins: the
		// left part may be forged by the client.
		{remote: "10.0.0.1:5000", xff: []string{"203.0.113.9, 198.51.100.1, 10.0.0.2"}, want: "198.51.100.1"},
		{remote: "10.0.0.1:5000", xff: []string{"203.0.113.9", "198.51.100.1,10.0.0.2"}, want: "198.51.100.1"},
		{remote: "10.0.0.1:5000", xff: []string{"10.0.0.3", "10.0.0.2"}},
		{remote: "10.0.0.1:5000", xff: []string{"[2001:db8::7]"}, want: "2001:db8::7"},
		{remote: "10.0.0.1:5000", xff: []string{"[198.51.100.1]"}},
		{remote: "[::1]:5000", xff: []string{"[2001:db8::1]:443"}, want: "2001:db8::1"},
		{remote: "[::ffff:10.0.0.1]:5000", xff: []string{"::ffff:198.51.100.1"}, want: "198.51.100.1"},
		// Garbage where an address is needed fails closed; garbage
		// beyond the client is never read.
		{remote: "10.0.0.1:5000", xff: []string{"unknown"}},
		{remote: "10.0.0.1:5000", xff: []string{"198.51.100.1,"}},
		{remote: "10.0.0.1:5000", xff: []string{"junk, 198.51.100.1"}, want: "198.51.100.1"},
		{remote: "@"},
	}
	for _, tt := range tests {
		r := request(http.MethodGet, "admin.example.com", tt.remote, nil)
		for _, v := range tt.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		got, err := g.ClientAddr(r)
		if tt.want == "" {
			if !errors.Is(err, ErrClientAddr) {
				t.Errorf("%s %q: %v, %v; want ErrClientAddr", tt.remote, tt.xff, got, err)
			}
			continue
		}
		if err != nil || got.String() != tt.want {
			t.Errorf("%s %q: %v, %v; want %s", tt.remote, tt.xff, got, err, tt.want)
		}
	}
	// A misspelt header name finds no client and fails closed.
	g = mustGuard(t, Config{Hosts: []string{"x"}, TrustedProxies: []string{"10.0.0.1"}, ForwardedHeader: "X-Forwarded-Fro"})
	r0 := request(http.MethodGet, "x", "10.0.0.1:1", map[string]string{"X-Forwarded-For": "198.51.100.7"})
	if _, err := g.ClientAddr(r0); !errors.Is(err, ErrClientAddr) {
		t.Errorf("misspelt header: %v", err)
	}
	for _, bad := range []string{"X Forwarded", "X-Forwarded-For:", "é"} {
		if _, err := New(Config{Hosts: []string{"x"}, ForwardedHeader: bad}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("ForwardedHeader %q: %v", bad, err)
		}
	}
	// Another header name.
	g = mustGuard(t, Config{Hosts: []string{"x"}, TrustedProxies: []string{"10.0.0.1"}, ForwardedHeader: "x-real-ip"})
	r := request(http.MethodGet, "x", "10.0.0.1:1", map[string]string{"X-Real-Ip": "198.51.100.7"})
	if got, err := g.ClientAddr(r); err != nil || got.String() != "198.51.100.7" {
		t.Errorf("X-Real-IP: %v, %v", got, err)
	}
}

func TestPeers(t *testing.T) {
	g := mustGuard(t, Config{
		Hosts:          []string{"admin.example.com"},
		Peers:          []string{"192.0.2.0/24", "2001:db8::/32", "::ffff:198.51.100.0/120"},
		TrustedProxies: []string{"10.0.0.1"},
	})
	for _, tt := range []struct {
		remote, xff string
		ok          bool
	}{
		{"192.0.2.9:1", "", true},
		{"[2001:db8::5]:1", "", true},
		{"198.51.100.4:1", "", true},
		{"203.0.113.1:1", "", false},
		{"10.0.0.1:1", "192.0.2.9", true},
		{"10.0.0.1:1", "203.0.113.1", false},
		{"10.0.0.1:1", "", false}, // the proxy itself is no allowed peer
		{"10.0.0.1:1", "bogus", false},
		{"@", "", false},
	} {
		h := map[string]string{}
		if tt.xff != "" {
			h["X-Forwarded-For"] = tt.xff
		}
		err := g.Check(request(http.MethodGet, "admin.example.com", tt.remote, h))
		if (err == nil) != tt.ok || (!tt.ok && !errors.Is(err, ErrPeer)) {
			t.Errorf("%s via %q: %v", tt.remote, tt.xff, err)
		}
	}
	// LoopbackPeers and Peers together allow either.
	g = mustGuard(t, Config{LoopbackHosts: true, LoopbackPeers: true, Peers: []string{"192.0.2.0/24"}})
	for remote, ok := range map[string]bool{"127.0.0.1:1": true, "192.0.2.1:1": true, "198.51.100.1:1": false} {
		if err := g.Check(request(http.MethodGet, "localhost", remote, nil)); (err == nil) != ok {
			t.Errorf("%s: %v", remote, err)
		}
	}
	for _, bad := range []string{"", "x", "10.0.0.0/33", "fe80::1%eth0", "::ffff:0:0/90"} {
		if _, err := New(Config{Hosts: []string{"x"}, Peers: []string{bad}}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Peers %q: %v", bad, err)
		}
		if _, err := New(Config{Hosts: []string{"x"}, TrustedProxies: []string{bad}}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("TrustedProxies %q: %v", bad, err)
		}
	}
}

func TestConfigJSON(t *testing.T) {
	var c Config
	data := `{"hosts":["admin.example.com"],"trusted_origins":["https://a.example.com"],"peers":["192.0.2.0/24"],` +
		`"trusted_proxies":["10.0.0.1"],"forwarded_header":"X-Real-IP","loopback_hosts":true,"loopback_peers":true,` +
		`"require_origin":true,"security_headers":true}`
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Hosts) != 1 || len(c.TrustedOrigins) != 1 || len(c.Peers) != 1 || len(c.TrustedProxies) != 1 ||
		c.ForwardedHeader != "X-Real-IP" || !c.LoopbackHosts || !c.LoopbackPeers || !c.RequireOrigin || !c.SecurityHeaders {
		t.Fatalf("got %+v", c)
	}
	if err := json.Unmarshal([]byte(`{"host":["x"]}`), &c); !errors.Is(err, ErrInvalidConfig) {
		t.Error(err)
	}
	var x CSRFConfig
	if err := json.Unmarshal([]byte(`{"key":"random","max_age":"1h","header":"X-T","field":"t","multipart_forms":true}`), &x); err != nil ||
		x.MaxAge != time.Hour || x.Header != "X-T" || x.Field != "t" || !x.MultipartForms {
		t.Fatalf("CSRFConfig %+v, %v", x, err)
	}
	for _, bad := range []string{`{"max_age":3600}`, `{"key":null}`, `{"hosts":null}`, `null`} {
		if err := json.Unmarshal([]byte(bad), &x); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	if err := json.Unmarshal([]byte(`{"max_age":"1h"}`), new(CSRFConfig)); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("missing CSRF key: %v", err)
	}
}

func TestCheckAllocs(t *testing.T) {
	g := mustGuard(t, Config{LoopbackHosts: true, LoopbackPeers: true, TrustedProxies: []string{"127.0.0.1"}})
	r := request(http.MethodGet, "localhost:8080", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "::1, 127.0.0.1"})
	if n := testing.AllocsPerRun(100, func() {
		if err := g.Check(r); err != nil {
			t.Fatal(err)
		}
	}); n != 0 {
		t.Fatalf("Check allocates %v times", n)
	}
}

func FuzzClientAddr(f *testing.F) {
	f.Add("10.0.0.1:1", "198.51.100.1, 10.0.0.2")
	f.Add("[::1]:1", "[2001:db8::1]:80,")
	f.Add("10.0.0.1:1", " , ")
	g := mustGuard(f, Config{Hosts: []string{"x"}, TrustedProxies: []string{"10.0.0.0/8", "::1"}})
	f.Fuzz(func(t *testing.T, remote, xff string) {
		r := request(http.MethodGet, "x", remote, map[string]string{"X-Forwarded-For": xff})
		addr, err := g.ClientAddr(r)
		if err != nil {
			if !errors.Is(err, ErrClientAddr) {
				t.Fatal(err)
			}
			return
		}
		if !addr.IsValid() || addr.Zone() != "" || addr.Is4In6() {
			t.Fatalf("ClientAddr(%q, %q) = %v", remote, xff, addr)
		}
		// The client is the peer, or an address from the header.
		if peer, _ := iaddr.Parse(remote); addr != peer && !contains(g.proxies, peer) {
			t.Fatalf("ClientAddr(%q, %q) = %v from an untrusted peer's header", remote, xff, addr)
		}
	})
}

// TestTrustedProxyWithoutHeader is a regression test: behind a local
// proxy whose forwarded header is missing or misnamed, a remote client
// must not pass LoopbackPeers as the proxy's address.
func TestTrustedProxyWithoutHeader(t *testing.T) {
	for _, header := range []string{"X-Forwarded-Fro", "X-Forwarded-For"} {
		c := LocalAdmin()
		c.TrustedProxies = []string{"127.0.0.1"}
		c.ForwardedHeader = header
		g := mustGuard(t, c)
		for _, h := range []map[string]string{{"X-Forwarded-Fro": "203.0.113.9"}, nil} {
			r := request(http.MethodGet, "localhost", "127.0.0.1:4000", h)
			// Without the configured header no client is named.
			missing := h[header] == ""
			if err := g.Check(r); !errors.Is(err, ErrPeer) || missing != errors.Is(err, ErrClientAddr) {
				t.Errorf("header %s, request %v: %v", header, h, err)
			}
		}
	}
}

func TestForwarded(t *testing.T) {
	g := mustGuard(t, Config{Hosts: []string{"x"}, TrustedProxies: []string{"10.0.0.1", "10.0.0.2"}, ForwardedHeader: "forwarded"})
	tests := []struct {
		fwd  []string
		want string // "" for an error
	}{
		{[]string{"for=192.0.2.60;proto=http;by=203.0.113.43"}, "192.0.2.60"},
		{[]string{`for="[2001:db8:cafe::17]:4711"`}, "2001:db8:cafe::17"},
		{[]string{`For="[2001:db8:cafe::17]"`}, "2001:db8:cafe::17"},
		{[]string{`for="192.0.2.43:47011"`}, "192.0.2.43"},
		{[]string{"for=198.51.100.17, for=10.0.0.2"}, "198.51.100.17"},
		{[]string{"for=203.0.113.9;by=x, for=198.51.100.17", "for=10.0.0.2"}, "198.51.100.17"},
		{[]string{"proto=https; for = 198.51.100.17"}, ""}, // no spaces around '='
		{[]string{"proto=https;for=198.51.100.17"}, "198.51.100.17"},
		// Anything left of the client is never read.
		{[]string{`for="_hidden", for=198.51.100.17`}, "198.51.100.17"},
		// Nodes that cannot be checked fail closed.
		{[]string{"for=unknown"}, ""},
		{[]string{"for=_hidden"}, ""},
		{[]string{`for="[2001:db8::1]:_port"`}, ""},
		{[]string{"for=2001:db8::1"}, "2001:db8::1"},
		{[]string{`for="198.51.100.1`}, ""},
		{[]string{`for="198\.51.100.1"`}, ""},
		{[]string{"proto=https"}, ""},
		{[]string{"for=198.51.100.1;for=198.51.100.2"}, ""},
		{[]string{"for"}, ""},
		{[]string{"for=10.0.0.2"}, ""},
		{nil, ""},
	}
	for _, tt := range tests {
		r := request(http.MethodGet, "x", "10.0.0.1:1", nil)
		for _, v := range tt.fwd {
			r.Header.Add("Forwarded", v)
		}
		got, err := g.ClientAddr(r)
		if tt.want == "" {
			if !errors.Is(err, ErrClientAddr) {
				t.Errorf("%q: %v, %v; want ErrClientAddr", tt.fwd, got, err)
			}
			continue
		}
		if err != nil || got.String() != tt.want {
			t.Errorf("%q: %v, %v; want %s", tt.fwd, got, err, tt.want)
		}
	}
}

func FuzzForwarded(f *testing.F) {
	f.Add(`for="[2001:db8::1]:80";proto=https, for=10.0.0.2`)
	f.Add("for=unknown")
	f.Add(`for=192.0.2.1;by="x;y"`)
	g := mustGuard(f, Config{Hosts: []string{"x"}, TrustedProxies: []string{"10.0.0.0/8"}, ForwardedHeader: "Forwarded"})
	f.Fuzz(func(t *testing.T, fwd string) {
		r := request(http.MethodGet, "x", "10.0.0.1:1", map[string]string{"Forwarded": fwd})
		addr, err := g.ClientAddr(r)
		if err != nil {
			if !errors.Is(err, ErrClientAddr) {
				t.Fatal(err)
			}
			return
		}
		if !addr.IsValid() || addr.Zone() != "" || addr.Is4In6() || contains(g.proxies, addr) {
			t.Fatalf("ClientAddr(%q) = %v", fwd, addr)
		}
	})
}

// TestRejectAllocs checks that same-origin checks by Referer, and
// rejections, do not allocate.
func TestRejectAllocs(t *testing.T) {
	g := mustGuard(t, Config{LoopbackHosts: true, LoopbackPeers: true, RequireOrigin: true})
	for _, r := range []*http.Request{
		request(http.MethodPost, "localhost:8080", "127.0.0.1:5000", map[string]string{"Referer": "http://localhost:8080/x"}),
		request(http.MethodPost, "localhost:8080", "127.0.0.1:5000", map[string]string{"Referer": "http://evil.example/x"}),
		request(http.MethodGet, "evil.example", "127.0.0.1:5000", nil),
		request(http.MethodGet, "localhost", "192.0.2.1:5000", nil),
		request(http.MethodGet, "localhost", "@", nil),
	} {
		if n := testing.AllocsPerRun(100, func() { _ = g.Check(r) }); n != 0 {
			t.Errorf("Check(%s %s from %s, %v) allocates %v times", r.Method, r.Host, r.RemoteAddr, r.Header, n)
		}
	}
	for ref, ok := range map[string]bool{
		"http://localhost:8080":        true,
		"HTTPS://localhost:8080/a?b#c": true,
		"http://localhost:8080?x":      true,
		"http://user@localhost:8080/":  false,
		"http://localhost:80801/":      false,
		"ftp://localhost:8080/":        false,
		"//localhost:8080/":            false,
		"http:///":                     false,
		"http://localhost:8080.evil/":  false,
	} {
		r := request(http.MethodPost, "localhost:8080", "127.0.0.1:5000", map[string]string{"Referer": ref})
		if got := sameOriginReferer(r); got != ok {
			t.Errorf("Referer %q: %v, want %v", ref, got, ok)
		}
	}
}

// TestLoopbackBehindLocalProxy is a regression test: a reverse proxy on
// the same host connects from loopback for remote clients, so a request
// it forwards must not pass LoopbackPeers when the proxy is not trusted.
func TestLoopbackBehindLocalProxy(t *testing.T) {
	g := mustGuard(t, LocalAdmin())
	for _, h := range []string{"X-Forwarded-For", "Forwarded", "X-Real-IP", "True-Client-IP", "X-Client-IP", "X-Forwarded-Host", "x-forwarded-for"} {
		r := request(http.MethodGet, "127.0.0.1:8080", "127.0.0.1:5000", map[string]string{h: "203.0.113.9"})
		if err := g.Check(r); !errors.Is(err, ErrPeer) {
			t.Errorf("%s from an untrusted loopback proxy: %v", h, err)
		}
	}
	if err := g.Check(request(http.MethodGet, "127.0.0.1:8080", "127.0.0.1:5000", nil)); err != nil {
		t.Fatalf("direct loopback client rejected: %v", err)
	}
	// Listed as a trusted proxy, the forwarded client is checked instead.
	c := LocalAdmin()
	c.TrustedProxies = []string{"127.0.0.1"}
	g = mustGuard(t, c)
	if err := g.Check(request(http.MethodGet, "localhost", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "203.0.113.9"})); !errors.Is(err, ErrPeer) {
		t.Fatalf("remote client through a trusted proxy: %v", err)
	}
	if err := g.Check(request(http.MethodGet, "localhost", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "::1"})); err != nil {
		t.Fatalf("local client through a trusted proxy: %v", err)
	}
	// Without peer checks, forwarding headers do not matter.
	g = mustGuard(t, Config{Hosts: []string{"x"}})
	if err := g.Check(request(http.MethodGet, "x", "127.0.0.1:5000", map[string]string{"X-Forwarded-For": "203.0.113.9"})); err != nil {
		t.Fatal(err)
	}
}

func TestConfigMarshalJSON(t *testing.T) {
	c := Config{Hosts: []string{"a"}, TrustedProxies: []string{"10.0.0.1"}, LoopbackPeers: true}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var got Config
	if err := json.Unmarshal(b, &got); err != nil || got.Hosts[0] != "a" || got.TrustedProxies[0] != "10.0.0.1" || !got.LoopbackPeers {
		t.Fatalf("%s -> %+v, %v", b, got, err)
	}
	b, err = json.Marshal(CSRFConfig{Key: testKey, PreviousKeys: [][]byte{testKey}, Skew: time.Second})
	if err != nil || strings.Contains(string(b), "key") || !strings.Contains(string(b), `"skew":"1s"`) {
		t.Fatalf("CSRFConfig JSON %s, %v", b, err)
	}
}
