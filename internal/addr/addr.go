// Package addr parses the IP addresses, with or without a port, that
// network peers and forwarding proxies report, without allocating for
// valid or invalid input.
package addr

import (
	"net/netip"
	"strings"
)

// Parse parses an IP address with or without a port: "ip", "ip:port",
// "[ipv6]" or "[ipv6]:port", as in net/http.Request.RemoteAddr,
// net.Addr.String or a forwarding header. It returns the address without
// its zone and with an IPv4-mapped address unmapped. It picks the parser
// by syntax, so that a valid address does not allocate a parse error
// first, and rejects names before netip would allocate an error for them.
func Parse(s string) (netip.Addr, bool) {
	var a netip.Addr
	var err error
	switch {
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		a, err = netip.ParseAddr(s[1 : len(s)-1])
		if err == nil && !a.Is6() {
			return netip.Addr{}, false
		}
	case hasPort(s):
		if ap, perr := netip.ParseAddrPort(s); perr == nil {
			a = ap.Addr()
		} else {
			err = perr
		}
	case strings.IndexByte(s, '%') >= 0 || IPChars(s):
		a, err = netip.ParseAddr(s)
	default:
		return netip.Addr{}, false
	}
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// hasPort reports whether s has the syntax of an address with a port:
// "[ipv6]:port" or "ipv4:port".
func hasPort(s string) bool {
	if s != "" && s[0] == '[' {
		return true
	}
	i := strings.IndexByte(s, ':')
	return i >= 0 && strings.IndexByte(s[i+1:], ':') < 0
}

// IPChars reports whether s is non-empty and consists of the characters
// of an IP address without a zone.
func IPChars(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F', c == '.', c == ':':
		default:
			return false
		}
	}
	return true
}
