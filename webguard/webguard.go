// Package webguard protects HTTP admin pages and APIs against DNS
// rebinding and cross-site request forgery.
//
// A Guard is middleware that checks, in order:
//
//   - the client address, optionally allowing loopback clients or listed
//     networks only;
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
// # Behind a reverse proxy
//
// Behind a reverse proxy, RemoteAddr is the proxy's address, often a
// loopback one. With LoopbackPeers or Peers, a request that carries a
// forwarding header from a peer outside TrustedProxies is rejected, so
// that LocalAdmin behind a proxy on the same host fails closed instead of
// admitting every remote client. List the proxies in TrustedProxies: ClientAddr then reads the client's address
// from ForwardedHeader, skipping trusted proxies from the right, and Peers
// apply to it. Every trusted host can claim any client address, so list
// the proxies themselves, not the network they live in. A request from a
// trusted proxy that names no client is rejected. Configure the proxy to
// pass the original Host header on, and list the public host names in
// Hosts:
//
//	g, err := webguard.New(webguard.Config{
//		Hosts:           []string{"admin.example.com"},
//		TrustedProxies:  []string{"10.0.0.2", "10.0.0.3"},
//		Peers:           []string{"192.0.2.0/24"}, // the office network
//		RequireOrigin:   true,
//		SecurityHeaders: true,
//	})
//
// # Allocation
//
// Check does not allocate, also when it rejects, except when a request
// carries Origin but no Sec-Fetch-Site: then CrossOriginProtection parses
// the Origin with net/url. CSRF.Verify and CSRF.Handler do not allocate
// either, except when the handler reads the token from a form body,
// which net/http parses.
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
// Host header and RemoteAddr as net/http reports them, and the forwarded
// header only as far as TrustedProxies say.
package webguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/textproto"
	"strings"

	"github.com/djylb/guard/internal/addr"
	"github.com/djylb/guard/internal/conf"
)

// Errors passed to Config.Deny and returned by Check. They are fixed
// values, so that rejecting a request does not allocate; Deny receives the
// request for details such as its Host and RemoteAddr.
var (
	// ErrPeer reports a client address that LoopbackPeers and Peers
	// reject, or that ClientAddr cannot determine.
	ErrPeer = errors.New("webguard: client address not allowed")
	// ErrClientAddr reports a RemoteAddr or forwarded address that is
	// not an IP address.
	ErrClientAddr = errors.New("webguard: invalid client address")
	// ErrHost reports a Host header that is not allowed.
	ErrHost = errors.New("webguard: host not allowed")
	// ErrCrossOrigin reports an unsafe request from another origin, or
	// with no evidence of its origin when RequireOrigin is set.
	ErrCrossOrigin = errors.New("webguard: cross-origin request")
	// ErrInvalidConfig reports a Config that New cannot use.
	ErrInvalidConfig = errors.New("webguard: invalid config")

	errPeerAddr  = fmt.Errorf("%w: %w", ErrPeer, ErrClientAddr)
	errForwarded = fmt.Errorf("%w: forwarded by a peer that is not a trusted proxy", ErrPeer)
	errNoOrigin  = fmt.Errorf("%w: no Origin, Sec-Fetch-Site or same-origin Referer", ErrCrossOrigin)
)

// Config configures a Guard.
type Config struct {
	// Deny writes the response to a rejected request. err wraps one of
	// the package's errors. It defaults to a plain 403 Forbidden.
	Deny func(w http.ResponseWriter, r *http.Request, err error)
	// Hosts lists the allowed Host header values: "name" or "ip" allows
	// any port, "name:port", "ip:port" and "[ipv6]:port" one port.
	// Names are compared case-insensitively and without a trailing dot.
	// Browsers leave the default port out of Host (80 for http, 443 for
	// https), so a rule with port 443 does not match their requests:
	// list "name" or "name:8443" as the server is reached.
	Hosts []string
	// TrustedOrigins lists origins, such as "https://admin.example.com",
	// whose unsafe requests are allowed although they are cross-origin.
	TrustedOrigins []string
	// Peers lists the client networks, as "ip" or "ip/bits", that are
	// allowed, such as a VPN's. The client is the one ClientAddr returns.
	Peers []string
	// TrustedProxies lists the reverse proxies, as "ip" or "ip/bits",
	// whose ForwardedHeader is believed. Every host in it can claim any
	// client address, so list the proxies' own addresses rather than a
	// whole network. Leave it empty when clients connect directly: anyone
	// can send the header.
	TrustedProxies []string
	// ForwardedHeader is the header in which trusted proxies append the
	// address of their peer, as a comma-separated list. It defaults to
	// X-Forwarded-For; a proxy that sends a single address, such as in
	// X-Real-IP, works too, and "Forwarded" reads the for parameters of
	// RFC 7239. It must be a valid header name.
	ForwardedHeader string
	// LoopbackHosts also allows the Host names that only a loopback
	// server answers to: "localhost" and loopback IP addresses, on any
	// port.
	LoopbackHosts bool
	// LoopbackPeers allows clients with a loopback address, protecting a
	// server accidentally bound to all interfaces. With LoopbackPeers or
	// Peers set, other clients are rejected, and so is every request over
	// a Unix socket, whose RemoteAddr is not an IP address; leave both
	// off there.
	//
	// A reverse proxy on the same host connects from loopback on behalf
	// of remote clients. So with LoopbackPeers or Peers set, a request
	// that carries ForwardedHeader, X-Forwarded-For, Forwarded,
	// X-Real-IP, True-Client-IP, X-Client-IP or X-Forwarded-Host is
	// rejected unless it comes from TrustedProxies: a peer
	// that forwards for someone else is not the client. List such a proxy
	// in TrustedProxies, and make sure it sends ForwardedHeader.
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

// jsonConfig is the JSON form of a Config.
type jsonConfig struct {
	Hosts           []string `json:"hosts,omitempty"`
	TrustedOrigins  []string `json:"trusted_origins,omitempty"`
	Peers           []string `json:"peers,omitempty"`
	TrustedProxies  []string `json:"trusted_proxies,omitempty"`
	ForwardedHeader string   `json:"forwarded_header"`
	LoopbackHosts   bool     `json:"loopback_hosts"`
	LoopbackPeers   bool     `json:"loopback_peers"`
	RequireOrigin   bool     `json:"require_origin"`
	SecurityHeaders bool     `json:"security_headers"`
}

//goland:noinspection GoMixedReceiverTypes
func (c *Config) json() jsonConfig {
	return jsonConfig{c.Hosts, c.TrustedOrigins, c.Peers, c.TrustedProxies, c.ForwardedHeader,
		c.LoopbackHosts, c.LoopbackPeers, c.RequireOrigin, c.SecurityHeaders}
}

// UnmarshalJSON reads a Config from a JSON object such as
//
//	{"hosts": ["admin.example.com"], "trusted_proxies": ["10.0.0.2", "10.0.0.3"], "require_origin": true}
//
// with the fields hosts, trusted_origins, loopback_hosts, loopback_peers,
// peers, trusted_proxies, forwarded_header, require_origin and
// security_headers. Fields that are absent keep their value; unknown,
// repeated and null fields are an error, and names must match exactly.
// Deny cannot be set from JSON.
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) UnmarshalJSON(data []byte) error {
	v := c.json()
	if err := conf.Decode(data, &v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	c.Hosts, c.TrustedOrigins, c.Peers, c.TrustedProxies = v.Hosts, v.TrustedOrigins, v.Peers, v.TrustedProxies
	c.ForwardedHeader, c.LoopbackHosts, c.LoopbackPeers = v.ForwardedHeader, v.LoopbackHosts, v.LoopbackPeers
	c.RequireOrigin, c.SecurityHeaders = v.RequireOrigin, v.SecurityHeaders
	return nil
}

// MarshalJSON writes c in the form UnmarshalJSON reads, without Deny.
//
//goland:noinspection GoMixedReceiverTypes
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.json())
}

// LocalAdmin returns the configuration for an admin server bound to a
// loopback address: loopback Host names and peers only, a same-origin
// Referer required when Origin and Sec-Fetch-Site are missing, and
// security headers. Requests forwarded by a reverse proxy on the same
// host are rejected (see LoopbackPeers); such a deployment is not local
// and needs Hosts, TrustedProxies and Peers instead.
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
	forwarded     string // canonical header name
	hosts         []hostRule
	peers         []netip.Prefix
	proxies       []netip.Prefix
	loopbackHosts bool
	loopbackPeers bool
	requireOrigin bool
	headers       bool
	rfc7239       bool // forwarded is the Forwarded header of RFC 7239
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
	var err error
	if g.peers, err = parsePrefixes(c.Peers); err != nil {
		return nil, err
	}
	if g.proxies, err = parsePrefixes(c.TrustedProxies); err != nil {
		return nil, err
	}
	g.forwarded = "X-Forwarded-For"
	if c.ForwardedHeader != "" {
		if !validToken(c.ForwardedHeader) {
			return nil, fmt.Errorf("%w: forwarded header %q is not a header name", ErrInvalidConfig, c.ForwardedHeader)
		}
		g.forwarded = textproto.CanonicalMIMEHeaderKey(c.ForwardedHeader)
	}
	g.rfc7239 = g.forwarded == "Forwarded"
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
	if g.loopbackPeers || len(g.peers) > 0 {
		a, proxied, err := g.clientAddr(r)
		if err != nil {
			return errPeerAddr
		}
		if !proxied && g.forwardedFor(r) {
			return errForwarded
		}
		if (!g.loopbackPeers || !a.IsLoopback()) && !contains(g.peers, a) {
			return ErrPeer
		}
	}
	if !g.allowedHost(r.Host) {
		return ErrHost
	}
	if g.cop.Check(r) != nil {
		return ErrCrossOrigin
	}
	if g.requireOrigin && !safeMethod(r.Method) &&
		r.Header.Get("Sec-Fetch-Site") == "" && r.Header.Get("Origin") == "" &&
		!sameOriginReferer(r) {
		return errNoOrigin
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

// sameOriginReferer reports whether the Referer is an http or https URL
// whose host and port equal the Host header. It compares by hand rather
// than with net/url, so that the check does not allocate.
func sameOriginReferer(r *http.Request) bool {
	ref := r.Header.Get("Referer")
	scheme, rest, ok := strings.Cut(ref, "://")
	if !ok || (!strings.EqualFold(scheme, "http") && !strings.EqualFold(scheme, "https")) {
		return false
	}
	host := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		host = rest[:i]
	}
	// Guard checked that Host is a valid, non-empty host, so user
	// information or an empty host never matches.
	return host == r.Host
}

// ClientAddr returns the address of the client that sent r, without its
// zone and with IPv4-mapped addresses unmapped. That is RemoteAddr,
// unless RemoteAddr is a trusted proxy: then ClientAddr walks the
// addresses in ForwardedHeader from the right, the last one appended
// first, skipping trusted proxies, and returns the first address that is
// not one.
//
// It fails closed, with an error wrapping ErrClientAddr, when an address
// it reads is not an IP address (such as RemoteAddr of a Unix socket, or
// an "unknown" or obfuscated Forwarded node), and when a trusted proxy
// sent no untrusted address at all, as when the header is missing or
// misnamed: it never returns a trusted proxy's own address. Use it to key
// per-client limits on the same address that Peers checks.
func (g *Guard) ClientAddr(r *http.Request) (netip.Addr, error) {
	if g == nil || g.cop == nil {
		return netip.Addr{}, ErrUninitialized
	}
	a, _, err := g.clientAddr(r)
	return a, err
}

// forwardedFor reports whether r carries a header in which proxies name
// the client they forward for.
func (g *Guard) forwardedFor(r *http.Request) bool {
	h := r.Header
	if len(h[g.forwarded]) > 0 {
		return true
	}
	for _, name := range forwardingHeaders {
		if len(h[name]) > 0 {
			return true
		}
	}
	return false
}

// forwardingHeaders are the canonical names of the headers in which
// proxies commonly name the client or the host they forward for.
var forwardingHeaders = [...]string{"X-Forwarded-For", "Forwarded", "X-Real-Ip", "True-Client-Ip", "X-Client-Ip", "X-Forwarded-Host"}

// clientAddr is ClientAddr, and also reports whether RemoteAddr is a
// trusted proxy.
func (g *Guard) clientAddr(r *http.Request) (netip.Addr, bool, error) {
	a, ok := addr.Parse(r.RemoteAddr)
	if !ok {
		return netip.Addr{}, false, ErrClientAddr
	}
	if !contains(g.proxies, a) {
		return a, false, nil
	}
	values := r.Header[g.forwarded]
	for i := len(values) - 1; i >= 0; i-- {
		list := values[i]
		for list != "" {
			hop := list
			if j := strings.LastIndexByte(list, ','); j >= 0 {
				hop, list = list[j+1:], list[:j]
			} else {
				list = ""
			}
			if g.rfc7239 {
				a, ok = rfc7239For(hop)
			} else {
				a, ok = addr.Parse(strings.TrimSpace(hop))
			}
			if !ok {
				return netip.Addr{}, true, ErrClientAddr
			}
			if !contains(g.proxies, a) {
				return a, true, nil
			}
		}
	}
	return netip.Addr{}, true, ErrClientAddr
}

// rfc7239For returns the address in the for parameter of one element of
// an RFC 7239 Forwarded header, such as for=192.0.2.1;proto=https or
// for="[2001:db8::1]:443". It fails for a missing or repeated for
// parameter and for "unknown" and obfuscated nodes, which cannot be
// checked against TrustedProxies.
func rfc7239For(element string) (netip.Addr, bool) {
	var node string
	found := false
	for element != "" {
		pair := element
		if j := strings.IndexByte(element, ';'); j >= 0 {
			pair, element = element[:j], element[j+1:]
		} else {
			element = ""
		}
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			return netip.Addr{}, false
		}
		if !strings.EqualFold(name, "for") {
			continue
		}
		if found {
			return netip.Addr{}, false
		}
		found = true
		if strings.HasPrefix(value, `"`) {
			if len(value) < 2 || value[len(value)-1] != '"' {
				return netip.Addr{}, false
			}
			// Quoted pairs and quotes left inside cannot form an
			// address, so addr.Parse rejects them.
			value = value[1 : len(value)-1]
		}
		node = value
	}
	if !found {
		return netip.Addr{}, false
	}
	return addr.Parse(node)
}

// validToken reports whether s is an HTTP token (RFC 9110), as a header
// name must be.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func contains(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// parsePrefixes parses "ip" and "ip/bits" entries; IPv4-mapped ones
// become IPv4, as client addresses are unmapped.
func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil || a.Zone() != "" {
				return nil, fmt.Errorf("%w: network %q", ErrInvalidConfig, s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if a := p.Addr(); a.Is4In6() {
			if p.Bits() < 96 {
				return nil, fmt.Errorf("%w: network %q", ErrInvalidConfig, s)
			}
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
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
	if !addr.IPChars(host) {
		return false
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
