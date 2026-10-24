// Package webguard protects HTTP admin pages and APIs against DNS
// rebinding and cross-site request forgery.
//
// A Guard is middleware that checks, in order:
//
//   - the client address, optionally allowing loopback peers only;
//   - the Host header against an allowlist, which stops DNS rebinding: a
//     malicious page whose name resolves to the server's address still
//     sends its own name as Host;
//   - that unsafe requests (other than GET, HEAD and OPTIONS) come from the
//     same origin, with net/http's CrossOriginProtection, which reads
//     Sec-Fetch-Site and Origin. Because the Host was checked first, the
//     Origin-to-Host comparison it falls back to cannot be fooled by a
//     rebound name. With RequireOrigin, requests that carry neither header
//     must have a same-origin Referer, which rejects non-browser clients
//     that send none of the three.
//
// CSRF adds per-session tokens on top, for defence in depth and for
// clients that send neither Sec-Fetch-Site nor Origin.
//
//	g, err := webguard.New(webguard.LocalAdmin())
//	...
//	http.ListenAndServe("127.0.0.1:8080", g.Handler(mux))
//
// # Relationship to CrossOriginProtection
//
// Guard builds on http.CrossOriginProtection rather than reimplementing it,
// and adds what it does not do: the Host allowlist that makes its Origin
// fallback safe, loopback-only peers, the optional Referer requirement and
// security headers. Applications that only need cross-origin checks can
// use http.CrossOriginProtection alone.
//
// # Cookies
//
// Session cookies of an admin page should be HttpOnly, SameSite=Lax or
// Strict, and Secure with the __Host- name prefix when served over HTTPS.
// SameSite does not protect against requests from sibling subdomains,
// which count as same-site; the cross-origin check and CSRF tokens do.
//
// # Limits
//
// Guard does not authenticate users, does not stop a malicious process on
// the same host, which can connect to loopback directly, and trusts the
// Host header and RemoteAddr as net/http reports them: behind a reverse
// proxy, list the public host names and leave LoopbackPeers off.
package webguard

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// Errors passed to Config.Deny and returned by Check. Each wraps the
// reason.
var (
	// ErrPeer reports a client address that LoopbackPeers rejects.
	ErrPeer = errors.New("webguard: client address not allowed")
	// ErrHost reports a Host header that is not allowed.
	ErrHost = errors.New("webguard: host not allowed")
	// ErrCrossOrigin reports an unsafe request from another origin, or
	// with no evidence of its origin when RequireOrigin is set.
	ErrCrossOrigin = errors.New("webguard: cross-origin request")
	// ErrInvalidConfig reports a Config that New cannot use.
	ErrInvalidConfig = errors.New("webguard: invalid config")
)

// Config configures a Guard.
type Config struct {
	// Deny writes the response to a rejected request. err wraps one of
	// the package's errors. It defaults to a plain 403 Forbidden.
	Deny func(w http.ResponseWriter, r *http.Request, err error)
	// Hosts lists the allowed Host header values: "name" or "ip" allows
	// any port, "name:port", "ip:port" and "[ipv6]:port" one port.
	// Names are compared case-insensitively and without a trailing dot.
	Hosts []string
	// TrustedOrigins lists origins, such as "https://admin.example.com",
	// whose unsafe requests are allowed although they are cross-origin.
	TrustedOrigins []string
	// LoopbackHosts also allows the Host names that only a loopback
	// server answers to: "localhost" and loopback IP addresses, on any
	// port.
	LoopbackHosts bool
	// LoopbackPeers rejects requests whose RemoteAddr is not a loopback
	// address, protecting a server accidentally bound to all interfaces.
	// It also rejects every request over a Unix socket, whose RemoteAddr
	// is not an IP address; leave it off there.
	LoopbackPeers bool
	// RequireOrigin rejects unsafe requests that carry neither
	// Sec-Fetch-Site nor Origin unless their Referer is same-origin.
	RequireOrigin bool
	// SecurityHeaders sets headers that keep the pages out of frames and
	// limit what they leak: X-Content-Type-Options: nosniff,
	// X-Frame-Options: DENY, Content-Security-Policy: frame-ancestors
	// 'none', Referrer-Policy: same-origin and Cross-Origin-Opener-Policy:
	// same-origin. Handlers may overwrite them.
	SecurityHeaders bool
}

// LocalAdmin returns the configuration for an admin server bound to a
// loopback address: loopback Host names and peers only, a same-origin
// Referer required when Origin and Sec-Fetch-Site are missing, and
// security headers.
func LocalAdmin() Config {
	return Config{LoopbackHosts: true, LoopbackPeers: true, RequireOrigin: true, SecurityHeaders: true}
}

type hostRule struct {
	host string // lower case, no trailing dot, no brackets
	port string // empty for any port
}

// Guard is HTTP middleware; see the package documentation. It is safe for
// concurrent use. Its zero value is not usable: create one with New.
type Guard struct {
	deny          func(http.ResponseWriter, *http.Request, error)
	cop           *http.CrossOriginProtection
	hosts         []hostRule
	loopbackHosts bool
	loopbackPeers bool
	requireOrigin bool
	headers       bool
}

// New returns a Guard configured by c. It requires at least one allowed
// host: Hosts or LoopbackHosts.
func New(c Config) (*Guard, error) {
	if len(c.Hosts) == 0 && !c.LoopbackHosts {
		return nil, fmt.Errorf("%w: no allowed hosts", ErrInvalidConfig)
	}
	g := &Guard{
		deny:          c.Deny,
		cop:           http.NewCrossOriginProtection(),
		loopbackHosts: c.LoopbackHosts,
		loopbackPeers: c.LoopbackPeers,
		requireOrigin: c.RequireOrigin,
		headers:       c.SecurityHeaders,
	}
	if g.deny == nil {
		g.deny = deny
	}
	for _, h := range c.Hosts {
		host, port, ok := splitHost(h, true)
		if !ok {
			return nil, fmt.Errorf("%w: host %q", ErrInvalidConfig, h)
		}
		g.hosts = append(g.hosts, hostRule{host: strings.ToLower(host), port: port})
	}
	for _, o := range c.TrustedOrigins {
		if err := g.cop.AddTrustedOrigin(o); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
	}
	return g, nil
}

func deny(w http.ResponseWriter, _ *http.Request, _ error) {
	http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
}

// Handler returns h guarded by g. Rejected requests go to Config.Deny. A
// zero Guard rejects every request.
func (g *Guard) Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g == nil || g.cop == nil {
			deny(w, r, ErrUninitialized)
			return
		}
		if g.headers {
			hd := w.Header()
			hd.Set("X-Content-Type-Options", "nosniff")
			hd.Set("X-Frame-Options", "DENY")
			hd.Set("Content-Security-Policy", "frame-ancestors 'none'")
			hd.Set("Referrer-Policy", "same-origin")
			hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		}
		if err := g.Check(r); err != nil {
			g.deny(w, r, err)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Check applies g's checks to r and returns the reason to reject it, or
// nil.
func (g *Guard) Check(r *http.Request) error {
	if g == nil || g.cop == nil {
		return ErrUninitialized
	}
	if g.loopbackPeers && !loopbackPeer(r.RemoteAddr) {
		return fmt.Errorf("%w: %q", ErrPeer, r.RemoteAddr)
	}
	if !g.allowedHost(r.Host) {
		return fmt.Errorf("%w: %q", ErrHost, r.Host)
	}
	if err := g.cop.Check(r); err != nil {
		return fmt.Errorf("%w: %w", ErrCrossOrigin, err)
	}
	if g.requireOrigin && !safeMethod(r.Method) &&
		r.Header.Get("Sec-Fetch-Site") == "" && r.Header.Get("Origin") == "" &&
		!sameOriginReferer(r) {
		return fmt.Errorf("%w: no Origin, Sec-Fetch-Site or same-origin Referer", ErrCrossOrigin)
	}
	return nil
}

func safeMethod(m string) bool {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func sameOriginReferer(r *http.Request) bool {
	ref := r.Header.Get("Referer")
	if ref == "" {
		return false
	}
	u, err := url.Parse(ref)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	return u.Host == r.Host
}

func loopbackPeer(remote string) bool {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	return ap.Addr().Unmap().IsLoopback()
}

func (g *Guard) allowedHost(h string) bool {
	host, port, ok := splitHost(h, false)
	if !ok {
		return false
	}
	if g.loopbackHosts && loopbackHost(host) {
		return true
	}
	for _, rule := range g.hosts {
		if strings.EqualFold(rule.host, host) && (rule.port == "" || rule.port == port) {
			return true
		}
	}
	return false
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Zone() == "" && a.Unmap().IsLoopback()
}

// splitHost splits a Host header value into its host, without brackets
// or a trailing dot, and port. It rejects malformed values, zones and
// characters outside host names and IP literals. bareIPv6 also accepts
// an IPv6 address without brackets, as in a configuration.
func splitHost(h string, bareIPv6 bool) (host, port string, ok bool) {
	if h == "" {
		return "", "", false
	}
	if bareIPv6 {
		if a, err := netip.ParseAddr(h); err == nil && a.Is6() && a.Zone() == "" {
			return h, "", true
		}
	}
	if h[0] == '[' {
		end := strings.IndexByte(h, ']')
		if end < 0 {
			return "", "", false
		}
		host, rest := h[1:end], h[end+1:]
		if a, err := netip.ParseAddr(host); err != nil || !a.Is6() || a.Zone() != "" {
			return "", "", false
		}
		if rest != "" {
			if rest[0] != ':' || !validPort(rest[1:]) {
				return "", "", false
			}
			port = rest[1:]
		}
		return host, port, true
	}
	host = h
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		host, port = h[:i], h[i+1:]
		if !validPort(port) {
			return "", "", false
		}
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", "", false
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_':
		default:
			return "", "", false
		}
	}
	return host, port, true
}

func validPort(p string) bool {
	if p == "" || len(p) > 5 {
		return false
	}
	n := 0
	for i := 0; i < len(p); i++ {
		if p[i] < '0' || p[i] > '9' {
			return false
		}
		n = n*10 + int(p[i]-'0')
	}
	return n <= 65535
}
