package failban

import (
	"errors"
	"net/netip"
)

// ErrInvalidAddr reports a remote address RemotePrefix cannot parse.
var ErrInvalidAddr = errors.New("failban: invalid address")

// Common prefix lengths for AddrPrefix: a single IPv4 address, and the
// IPv6 /64 a single host or subscriber usually controls in full.
const (
	HostBitsV4 = 32
	SiteBitsV6 = 64
)

// AddrPrefix returns the network of addr that a key should cover: the
// first v4Bits bits of an IPv4 address, or of an IPv4-mapped IPv6 address,
// and the first v6Bits bits of other IPv6 addresses. Lengths outside the
// address size are clamped to it. The zone is dropped. It returns the zero
// Prefix for the zero Addr.
//
// Keying IPv6 clients by a single address lets one host rotate through
// billions of keys; a /64 or /56 per key avoids that.
func AddrPrefix(addr netip.Addr, v4Bits, v6Bits int) netip.Prefix {
	if !addr.IsValid() {
		return netip.Prefix{}
	}
	addr = addr.Unmap().WithZone("")
	n := v6Bits
	if addr.Is4() {
		n = v4Bits
	}
	n = min(max(n, 0), addr.BitLen())
	p, _ := addr.Prefix(n) // cannot fail: the length is in range
	return p
}

// RemotePrefix is AddrPrefix for an address in the form of
// net/http.Request.RemoteAddr or net.Addr.String: "ip:port",
// "[ipv6]:port", or an IP address alone.
func RemotePrefix(remote string, v4Bits, v6Bits int) (netip.Prefix, error) {
	addr, err := netip.ParseAddr(remote)
	if err != nil {
		ap, perr := netip.ParseAddrPort(remote)
		if perr != nil {
			return netip.Prefix{}, ErrInvalidAddr
		}
		addr = ap.Addr()
	}
	return AddrPrefix(addr, v4Bits, v6Bits), nil
}
