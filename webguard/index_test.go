package webguard

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// linearHost and linearContains are the linear scans that hostSet and
// prefixSet replace; the differential tests hold the indexes to them.
type linearHost struct{ host, port string }

func linearAllowed(rules []linearHost, host, port string) bool {
	for _, rule := range rules {
		if strings.EqualFold(rule.host, host) && (rule.port == "" || rule.port == port) {
			return true
		}
	}
	return false
}

func linearContains(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// linearPrefixes parses like parsePrefixes but keeps every network in
// configuration order.
func linearPrefixes(tb testing.TB, list []string) []netip.Prefix {
	tb.Helper()
	var out []netip.Prefix
	for _, s := range list {
		p, err := parsePrefixes([]string{s})
		if err != nil {
			tb.Fatal(err)
		}
		out = append(out, p...)
	}
	return out
}

// byteN returns a byte in [0, n), n at most 256.
func byteN(r *rand.Rand, n int) byte {
	return byte(r.IntN(n)) //nolint:gosec // G115: n is at most 256
}

// v4 returns the address 10.0.0.0 + i, i below 1<<24.
func v4(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}) //nolint:gosec // G115: the bytes of i are wanted
}

func randHostName(r *rand.Rand) string {
	labels := []string{"a", "B", "admin", "ADMIN", "Example", "com", "x-y", "_s", "1", "local"}
	n := 1 + r.IntN(3)
	var b strings.Builder
	for i := range n {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(labels[r.IntN(len(labels))])
	}
	switch r.IntN(8) {
	case 0:
		return []string{"::1", "::FFFF:7f00:1", "2001:DB8::1", "2001:db8::1", "10.0.0.1", "127.0.0.1"}[r.IntN(6)]
	case 1:
		b.WriteByte('.')
	}
	return b.String()
}

func randPort(r *rand.Rand) string {
	return []string{"", "", "80", "080", "443", "8080", "65535", "1"}[r.IntN(8)]
}

func randHostValue(r *rand.Rand, bracket bool) string {
	h, port := randHostName(r), randPort(r)
	if strings.Contains(h, ":") {
		if port == "" && !bracket {
			return h
		}
		h = "[" + h + "]"
	}
	if port != "" {
		h += ":" + port
	}
	return h
}

func TestHostSetMatchesLinear(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // G404: a reproducible sequence is the point
	for round := range 300 {
		rules := make([]linearHost, 0, 12)
		var set hostSet
		for range r.IntN(cap(rules)) {
			host, port, ok := splitHost(randHostValue(r, r.IntN(2) == 0), true)
			if !ok {
				t.Fatal("generated an invalid rule")
			}
			rules = append(rules, linearHost{strings.ToLower(host), port})
			set.add(host, port)
		}
		for range 200 {
			v := randHostValue(r, true)
			host, port, ok := splitHost(v, false)
			if !ok {
				continue
			}
			if got, want := set.allows(host, port), linearAllowed(rules, host, port); got != want {
				t.Fatalf("round %d: %q with rules %v: got %v, want %v", round, v, rules, got, want)
			}
		}
	}
}

// TestHostSetCases pins the cases the index has to get right: case,
// trailing dots, ports with leading zeros, bracketed IPv6 and keys
// longer than the stack buffer.
func TestHostSetCases(t *testing.T) {
	long := strings.Repeat("a", hostKeyBuf+10)
	g := mustGuard(t, Config{Hosts: []string{"Admin.Example.com.", "api.example.com:8443", "::1", "[2001:DB8::1]:80", long, long[:hostKeyBuf-2] + ":80"}})
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"admin.example.com", true},
		{"ADMIN.EXAMPLE.COM.:9", true},
		{"admin.example.co", false},
		{"dmin.example.com", false},
		{"api.example.com:8443", true},
		{"API.example.com.:8443", true},
		{"api.example.com", false},
		{"api.example.com:08443", false},
		{"api.example.com:443", false},
		{"[::1]:1", true},
		{"[2001:db8::1]:80", true},
		{"[2001:db8::1]", false},
		{"[2001:db8::1]:81", false},
		{strings.ToUpper(long) + ":1", true},
		{long + "a", false},
		{long[:hostKeyBuf-2] + ":80", true},
		{long[:hostKeyBuf-2] + ":8", false},
		{long[:hostKeyBuf-2], false},
	} {
		if got := g.allowedHost(tc.host); got != tc.want {
			t.Errorf("allowedHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func randPrefix(r *rand.Rand) string {
	// A small address space, so that networks nest and overlap often.
	switch r.IntN(4) {
	case 0:
		a := netip.AddrFrom4([4]byte{10, byteN(r, 4), byteN(r, 4), byteN(r, 8)})
		if r.IntN(3) == 0 {
			return a.String()
		}
		return fmt.Sprintf("%s/%d", a, r.IntN(33))
	case 1:
		a := netip.AddrFrom4([4]byte{192 * byteN(r, 2), 0, byteN(r, 3), byteN(r, 4)})
		return fmt.Sprintf("::ffff:%s/%d", a, 96+r.IntN(33))
	default:
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byteN(r, 8), 14: byteN(r, 2), 7: byteN(r, 2)})
		if r.IntN(3) == 0 {
			return a.String()
		}
		return fmt.Sprintf("%s/%d", a, r.IntN(129))
	}
}

func randAddr(r *rand.Rand) netip.Addr {
	switch r.IntN(5) {
	case 0:
		return netip.AddrFrom4([4]byte{10, byteN(r, 5), byteN(r, 5), byteN(r, 9)})
	case 1:
		return netip.AddrFrom4([4]byte{192 * byteN(r, 2), 0, byteN(r, 3), byteN(r, 4)})
	case 2:
		return netip.AddrFrom4([4]byte{byteN(r, 256), byteN(r, 256), byteN(r, 256), byteN(r, 256)})
	case 3:
		return netip.AddrFrom16([16]byte{0xff, 15: byteN(r, 3)})
	default:
		return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byteN(r, 9), 14: byteN(r, 3), 7: byteN(r, 3)})
	}
}

func TestPrefixSetMatchesLinear(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4)) //nolint:gosec // G404: a reproducible sequence is the point
	for round := range 500 {
		list := make([]string, 0, 16)
		for range r.IntN(cap(list)) {
			list = append(list, randPrefix(r))
		}
		set, err := parsePrefixes(list)
		if err != nil {
			t.Fatal(err)
		}
		linear := linearPrefixes(t, list)
		for range 300 {
			a := randAddr(r)
			if got, want := set.contains(a), linearContains(linear, a); got != want {
				t.Fatalf("round %d: %v in %v: got %v, want %v", round, a, list, got, want)
			}
		}
	}
}

// TestPrefixSetCases pins nesting in either order, both families and the
// edges of a network.
func TestPrefixSetCases(t *testing.T) {
	set, err := parsePrefixes([]string{"10.1.2.0/24", "10.0.0.0/8", "10.1.0.0/16", "192.0.2.7", "2001:db8::/32", "::ffff:198.51.100.0/120", "0.0.0.0/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != 5 {
		t.Errorf("nested networks kept: %v", set)
	}
	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"10.0.0.0", true},
		{"10.255.255.255", true},
		{"10.1.2.3", true},
		{"11.0.0.0", false},
		{"9.255.255.255", false},
		{"192.0.2.7", true},
		{"192.0.2.6", false},
		{"192.0.2.8", false},
		{"198.51.100.255", true},
		{"0.0.0.0", true},
		{"0.0.0.1", false},
		{"2001:db8:ffff::1", true},
		{"2001:db9::", false},
		{"::", false},
		{"::ffff:10.0.0.1", false}, // mapped addresses are unmapped before lookup
	} {
		if got := set.contains(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("contains(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
	var empty prefixSet
	if empty.contains(netip.MustParseAddr("10.0.0.1")) || empty.contains(netip.Addr{}) {
		t.Error("empty set contains an address")
	}
}

func TestIndexLookupsDoNotAllocate(t *testing.T) {
	g := mustGuard(t, Config{Hosts: []string{"admin.example.com", "api.example.com:8443"}, Peers: []string{"10.0.0.0/8", "2001:db8::/32"}})
	a := netip.MustParseAddr("2001:db8::1")
	if n := testing.AllocsPerRun(100, func() {
		_ = g.allowedHost("API.Example.com:8443")
		_ = g.allowedHost("other.example.com:8443")
		_ = g.peers.contains(a)
	}); n != 0 {
		t.Errorf("%v allocations", n)
	}
}

func benchHosts(n int) ([]string, []string) {
	cfg := make([]string, n)
	for i := range n {
		cfg[i] = "host" + strconv.Itoa(i) + ".example.com"
		if i%2 == 1 {
			cfg[i] += ":8443"
		}
	}
	// A hit near the end and a miss: the linear scan's worst cases.
	return cfg, []string{"Host" + strconv.Itoa(n-1) + ".example.com:8443", "nohost.example.com:8443"}
}

func BenchmarkHostLookup(b *testing.B) {
	for _, n := range []int{10, 1_000_000} {
		cfg, probes := benchHosts(n)
		g := mustGuard(b, Config{Hosts: cfg})
		var rules []linearHost
		for _, h := range cfg {
			host, port, _ := splitHost(h, true)
			rules = append(rules, linearHost{strings.ToLower(host), port})
		}
		for _, impl := range []string{"linear", "index"} {
			b.Run(fmt.Sprintf("%s/%d", impl, n), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; b.Loop(); i++ {
					host, port, _ := splitHost(probes[i&1], false)
					if impl == "linear" {
						_ = linearAllowed(rules, host, port)
					} else {
						_ = g.hosts.allows(host, port)
					}
				}
			})
		}
	}
}

func BenchmarkPrefixLookup(b *testing.B) {
	for _, n := range []int{10, 1_000_000} {
		list := make([]string, n)
		for i := range n {
			list[i] = v4(i).String() + "/32"
		}
		set, err := parsePrefixes(list)
		if err != nil {
			b.Fatal(err)
		}
		linear := linearPrefixes(b, list)
		probes := []netip.Addr{v4(n - 1), netip.MustParseAddr("192.0.2.1")}
		for _, impl := range []string{"linear", "index"} {
			b.Run(fmt.Sprintf("%s/%d", impl, n), func(b *testing.B) {
				b.ReportAllocs()
				for i := 0; b.Loop(); i++ {
					if impl == "linear" {
						_ = linearContains(linear, probes[i&1])
					} else {
						_ = set.contains(probes[i&1])
					}
				}
			})
		}
	}
}
