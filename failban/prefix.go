package failban

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/djylb/guard/internal/addr"
)

// ErrInvalidAddr reports a remote address PrefixLen.OfRemote cannot parse.
var ErrInvalidAddr = errors.New("failban: invalid address")

// ErrInvalidPrefixLen reports a negative length, which PrefixLen.Validate
// and OfRemote return.
var ErrInvalidPrefixLen = errors.New("failban: negative prefix length")

// PrefixLen gives the length of the network prefix that a key covers, in
// bits, for IPv4 and for IPv6 addresses. Keying IPv6 clients by a single
// address lets one host rotate through billions of keys: a single host or
// subscriber usually controls a whole /64, often a /56 or /48. A typical
// per-client key is PrefixLen{V4: 32, V6: 64}; a limiter keyed by a wider
// network, such as PrefixLen{V4: 24, V6: 48}, in front of it keeps one
// network from filling the ban table.
//
// A zero field means the full address length, /32 or /128, so that a
// field left out never lumps every client of that family under one key.
// Negative lengths are invalid.
type PrefixLen struct {
	V4 int `json:"v4"`
	V6 int `json:"v6"`
}

// Of returns the network of addr that a key covers: the first V4 bits of
// an IPv4 address, or of an IPv4-mapped IPv6 address, and the first V6
// bits of other IPv6 addresses. Zero and lengths beyond the address size
// mean the full address. The zone is dropped. It returns the zero Prefix
// for the zero Addr. It panics on a negative length, which Validate
// reports, rather than put every address under one key.
func (p PrefixLen) Of(addr netip.Addr) netip.Prefix {
	if !addr.IsValid() {
		return netip.Prefix{}
	}
	addr = addr.Unmap().WithZone("")
	n := p.V6
	if addr.Is4() {
		n = p.V4
	}
	if n < 0 {
		panic(ErrInvalidPrefixLen)
	}
	if n == 0 || n > addr.BitLen() {
		n = addr.BitLen()
	}
	prefix, _ := addr.Prefix(n) // cannot fail: the length is in range
	return prefix
}

// OfRemote is Of for an address in the form of net/http.Request.RemoteAddr
// or net.Addr.String: "ip:port", "[ipv6]:port", "[ipv6]", or an IP address
// alone. It does not allocate.
// It fails with ErrInvalidPrefixLen when a length is negative.
func (p PrefixLen) OfRemote(remote string) (netip.Prefix, error) {
	if err := p.Validate(); err != nil {
		return netip.Prefix{}, err
	}
	a, ok := addr.Parse(remote)
	if !ok {
		return netip.Prefix{}, ErrInvalidAddr
	}
	return p.Of(a), nil
}

// Validate returns an error matching ErrInvalidPrefixLen, which names the
// length, when one is negative.
func (p PrefixLen) Validate() error {
	if p.V4 < 0 {
		return fmt.Errorf("%w: V4 %d", ErrInvalidPrefixLen, p.V4)
	}
	if p.V6 < 0 {
		return fmt.Errorf("%w: V6 %d", ErrInvalidPrefixLen, p.V6)
	}
	return nil
}
