package failban

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	ns atomic.Int64
}

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	return c
}

func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

func newTest(t testing.TB, clk *fakeClock, c Config) *Limiter[string] {
	t.Helper()
	c.Now = clk.Now
	l, err := New[string](c)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func failN(l *Limiter[string], key string, n int) (time.Time, bool) {
	var until time.Time
	var banned bool
	for range n {
		until, banned = l.Fail(key)
	}
	return until, banned
}

func TestBan(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 3, Window: time.Minute, BanDuration: 10 * time.Minute})
	if _, banned := failN(l, "u", 2); banned || l.IsBanned("u") {
		t.Fatal("banned below threshold")
	}
	if got := l.Failures("u"); got != 2 {
		t.Fatalf("Failures = %d", got)
	}
	until, banned := l.Fail("u")
	if !banned || !until.Equal(clk.Now().Add(10*time.Minute)) {
		t.Fatalf("Fail = %v, %v", until, banned)
	}
	if got, ok := l.BannedUntil("u"); !ok || !got.Equal(until) {
		t.Fatalf("BannedUntil = %v, %v", got, ok)
	}
	if l.IsBanned("v") {
		t.Fatal("other key banned")
	}
	// Failures while banned neither count nor extend the ban.
	clk.Advance(time.Minute)
	if got, _ := l.Fail("u"); !got.Equal(until) {
		t.Fatalf("ban extended to %v", got)
	}
	if l.Failures("u") != 0 {
		t.Fatal("failure counted while banned")
	}
	clk.Advance(9*time.Minute - 1)
	if !l.IsBanned("u") {
		t.Fatal("ban ended early")
	}
	clk.Advance(1)
	if l.IsBanned("u") {
		t.Fatal("ban did not end")
	}
}

func TestWindow(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 3, Window: 70 * time.Second})
	// Failures further apart than 8/7 of the window never add up.
	for range 10 {
		if _, banned := l.Fail("u"); banned {
			t.Fatal("banned for spread-out failures")
		}
		clk.Advance(41 * time.Second)
	}
	// Failures within the window always do.
	l.Succeed("u")
	l.Fail("u")
	clk.Advance(35 * time.Second)
	l.Fail("u")
	clk.Advance(35 * time.Second)
	if _, banned := l.Fail("u"); !banned {
		t.Fatal("not banned for failures within the window")
	}
}

func TestWindowCoverage(t *testing.T) {
	// Every pair of failures less than Window apart is counted
	// together, wherever the bucket boundaries fall.
	const window = 70 * time.Second
	for offset := time.Duration(0); offset < 10*time.Second; offset += 700 * time.Millisecond {
		clk := newFakeClock()
		l := newTest(t, clk, Config{Threshold: 2, Window: window})
		clk.Advance(offset)
		l.Fail("u")
		clk.Advance(window)
		if _, banned := l.Fail("u"); !banned {
			t.Fatalf("offset %v: failures Window apart not counted together", offset)
		}
	}
}

func TestGrowth(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 1, BanDuration: time.Minute, MaxBanDuration: 5 * time.Minute, Cooldown: time.Hour})
	for i, want := range []time.Duration{1, 2, 4, 5, 5} {
		until, banned := l.Fail("u")
		if !banned || until.Sub(clk.Now()) != want*time.Minute {
			t.Fatalf("ban %d: %v, want %v", i+1, until.Sub(clk.Now()), want*time.Minute)
		}
		clk.Advance(until.Sub(clk.Now()))
	}
	if bans := l.Bans(); len(bans) != 0 {
		t.Fatalf("Bans = %v", bans)
	}
	// After the cooldown, offences are forgotten.
	clk.Advance(time.Hour)
	if until, _ := l.Fail("u"); until.Sub(clk.Now()) != time.Minute {
		t.Fatalf("after cooldown: %v", until.Sub(clk.Now()))
	}
	// Unban forgets them too.
	clk.Advance(time.Minute)
	l.Fail("u")
	if !l.Unban("u") || l.IsBanned("u") {
		t.Fatal("Unban")
	}
	if until, _ := l.Fail("u"); until.Sub(clk.Now()) != time.Minute {
		t.Fatalf("after Unban: %v", until.Sub(clk.Now()))
	}
	if l.Unban("never") {
		t.Fatal("Unban of an unknown key")
	}
}

func TestDuration(t *testing.T) {
	l := &Limiter[int]{ban: 3, maxBan: 1<<62 + 5}
	if d := l.duration(math.MaxInt); d != l.maxBan {
		t.Fatalf("duration = %d", d)
	}
	if d := l.duration(2); d != 6 {
		t.Fatalf("duration = %d", d)
	}
}

func TestHugeWindow(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 3, Window: math.MaxInt64})
	failN(l, "u", 2)
	clk.Advance(1000 * time.Hour)
	if _, banned := l.Fail("u"); !banned {
		t.Fatal("not banned with an unbounded window")
	}
}

func TestSucceed(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 2})
	l.Fail("u")
	l.Succeed("u")
	if _, banned := l.Fail("u"); banned {
		t.Fatal("Succeed did not reset the count")
	}
	l.Fail("u")
	l.Succeed("u")
	if !l.IsBanned("u") {
		t.Fatal("Succeed lifted a ban")
	}
}

func TestIsBannedReadOnly(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 1, BanDuration: time.Minute})
	l.Fail("u")
	before := l.Stats()
	clk.Advance(2 * time.Minute)
	for _, k := range []string{"u", "v"} {
		l.IsBanned(k)
		l.BannedUntil(k)
		l.Failures(k)
	}
	l.Bans()
	if before.Banned != 1 {
		t.Fatalf("Stats before = %+v", before)
	}
	total := 0
	for i := range l.shards {
		total += len(l.shards[i].bans)
	}
	if total != 1 {
		t.Fatal("a read-only call removed the expired record")
	}
	l.Sweep()
	if st := l.Stats(); st != (Stats{}) {
		t.Fatalf("Stats after Sweep = %+v", st)
	}
}

// TestEvictionKeepsBans floods the limiter with new keys and checks that
// bans survive counter eviction.
func TestEvictionKeepsBans(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 3, Capacity: 16, MaxBans: 64, Shards: 1})
	failN(l, "victim", 2)
	failN(l, "attacker", 3)
	for i := range 1000 {
		l.Fail(fmt.Sprint("flood", i))
	}
	if !l.IsBanned("attacker") {
		t.Fatal("flooding lifted a ban")
	}
	if l.Failures("victim") != 0 {
		t.Fatal("least recent counter not evicted")
	}
	if st := l.Stats(); st.Pending != 16 || st.Banned != 1 {
		t.Fatalf("Stats = %+v", st)
	}
}

func TestEvictSoonest(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 1, BanDuration: time.Minute, Cooldown: time.Hour, Capacity: 16, MaxBans: 2, Shards: 1, Full: EvictSoonest})
	l.Fail("a")
	clk.Advance(time.Second)
	l.Fail("b")
	until, banned := l.Fail("c")
	if !banned || !until.Equal(clk.Now().Add(time.Minute)) {
		t.Fatalf("Fail(c) = %v, %v", until, banned)
	}
	if l.IsBanned("a") || !l.IsBanned("b") || !l.IsBanned("c") || l.IsBanned("innocent") {
		t.Fatal("the soonest-ending ban was not the one evicted")
	}
	if st := l.Stats(); st.Evicted != 1 || st.Banned != 2 || st.LockedShards != 0 {
		t.Fatalf("Stats = %+v", st)
	}
	// Records of ended bans make room before any active ban is evicted.
	clk.Advance(time.Minute)
	l.Fail("d")
	if !l.IsBanned("d") || l.Stats().Evicted != 1 {
		t.Fatalf("an ended ban was not dropped first: %+v", l.Stats())
	}
}

func TestLockShard(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 2, BanDuration: time.Minute, Capacity: 16, MaxBans: 2, Shards: 1, Full: LockShard})
	failN(l, "a", 2)
	clk.Advance(time.Second)
	failN(l, "b", 2)
	// The table is full of active bans: c cannot get a record, so the
	// shard locks down until a's ban ends.
	l.Fail("c")
	until, banned := l.Fail("c")
	if !banned || !until.Equal(clk.Now().Add(time.Minute-time.Second)) {
		t.Fatalf("Fail(c) = %v, %v", until, banned)
	}
	if !l.IsBanned("c") || !l.IsBanned("innocent") {
		t.Fatal("shard not locked down")
	}
	if st := l.Stats(); st.LockedShards != 1 || st.Waiting != 1 || st.Evicted != 0 {
		t.Fatalf("Stats = %+v", st)
	}
	clk.Advance(time.Minute - time.Second)
	// The lockdown is over, and c is banned without another attempt,
	// before any call gives it a record.
	if l.IsBanned("innocent") {
		t.Fatal("lockdown outlived the earliest ban")
	}
	if got, ok := l.BannedUntil("c"); !ok || !got.Equal(clk.Now().Add(time.Minute)) {
		t.Fatalf("waiting key after the lockdown: %v, %v", got, ok)
	}
	l.Sweep() // a's record is dropped and c gets one
	found := false
	for _, b := range l.Bans() {
		found = found || b.Key == "c"
	}
	if !found || !l.IsBanned("b") || l.Stats().Waiting != 0 {
		t.Fatalf("c not banned once a record was free: %v %+v", l.Bans(), l.Stats())
	}
	if l.IsBanned("innocent") {
		t.Fatal("still locked down")
	}
}

func TestLockShardThresholdExact(t *testing.T) {
	// The key that reaches Threshold during a lockdown gets no extra
	// attempt afterwards: its next Fail returns banned with its own ban.
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 3, BanDuration: time.Minute, Capacity: 16, MaxBans: 1, Shards: 1, Full: LockShard})
	failN(l, "a", 3)
	failN(l, "c", 3)
	clk.Advance(time.Minute)
	if _, banned := l.Fail("c"); !banned {
		t.Fatal("extra attempt after the lockdown")
	}
	if until, ok := l.BannedUntil("c"); !ok || !until.Equal(clk.Now().Add(time.Minute)) {
		t.Fatalf("c's ban: %v, %v", until, ok)
	}
}

func TestLockShardWaitingSurvivesFlood(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 1, Capacity: 4, MaxBans: 1, Shards: 1, Full: LockShard})
	l.Fail("a")
	l.Fail("c") // waits for a record
	for i := range 100 {
		l.Fail(fmt.Sprint("flood", i))
	}
	if st := l.Stats(); st.Waiting == 0 || st.Pending > 4 {
		t.Fatalf("waiting counter evicted by a flood: %+v", st)
	}
	clk.Advance(DefaultBanDuration)
	if !l.IsBanned("c") {
		t.Fatal("waiting key lost its ban to a flood")
	}
}

func TestLockdownUnban(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 1, Capacity: 4, MaxBans: 1, Shards: 1, Full: LockShard})
	l.Fail("a")
	l.Fail("b")
	if !l.IsBanned("x") {
		t.Fatal("not locked down")
	}
	l.Unban("a")
	if l.IsBanned("x") || !l.IsBanned("b") {
		t.Fatal("Unban did not end the lockdown and ban the waiting key")
	}
	l.Reset()
	if l.Stats() != (Stats{}) || l.IsBanned("b") {
		t.Fatal("Reset")
	}
}

func TestBansOrder(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 1, BanDuration: time.Hour})
	for i := range 20 {
		l.Fail(fmt.Sprint(i))
		clk.Advance(time.Second)
	}
	bans := l.Bans()
	if len(bans) != 20 {
		t.Fatalf("%d bans", len(bans))
	}
	for i, b := range bans {
		if b.Key != fmt.Sprint(i) || b.Offences != 1 {
			t.Fatalf("ban %d = %+v", i, b)
		}
	}
	// Remove from the middle of the heap and check the rest.
	l.Unban("7")
	clk.Advance(time.Hour - 15*time.Second)
	l.Sweep()
	if st := l.Stats(); st.Banned != 13 {
		t.Fatalf("Stats = %+v", st)
	}
}

func TestClockBack(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 2})
	clk.Advance(-time.Hour) // before New
	l.Fail("u")
	clk.Advance(-time.Hour)
	if _, banned := l.Fail("u"); !banned {
		t.Fatal("failures before a clock step back not counted")
	}
}

func TestConfig(t *testing.T) {
	bad := []Config{
		{Threshold: -1},
		{Window: -1},
		{BanDuration: time.Hour, MaxBanDuration: time.Minute},
		{Capacity: -1},
		{MaxBans: -1},
		{Shards: -1},
		{Cooldown: -1},
		{Full: FullPolicy(7)},
	}
	for _, c := range bad {
		if _, err := New[string](c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("New(%+v) = %v", c, err)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("MustNew did not panic")
			}
		}()
		MustNew[int](Config{Threshold: -1})
	}()
	if FullPolicy(7).String() != "FullPolicy(7)" || LockShard.String() != "LockShard" {
		t.Error("FullPolicy.String")
	}
	l := MustNew[int](Config{Capacity: 3, MaxBans: 100, Shards: 64})
	if len(l.shards) != 2 {
		t.Fatalf("%d shards", len(l.shards))
	}
	if l.cooldown != 0 {
		t.Fatal("cooldown without growth")
	}
	l = MustNew[int](Config{BanDuration: time.Minute, MaxBanDuration: time.Hour})
	if l.cooldown != int64(time.Hour) {
		t.Fatal("default cooldown")
	}
}

func TestConcurrent(t *testing.T) {
	for _, full := range []FullPolicy{EvictSoonest, LockShard} {
		t.Run(full.String(), func(t *testing.T) { testConcurrent(t, full) })
	}
}

func testConcurrent(t *testing.T, full FullPolicy) {
	l := MustNew[int](Config{Threshold: 3, Capacity: 32, MaxBans: 16, Full: full})
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			for i := range 2000 {
				k := (g*7 + i) % 100
				switch i % 6 {
				case 0:
					l.Succeed(k)
				case 1:
					l.IsBanned(k)
				case 2:
					l.Failures(k)
				case 3:
					a := l.Attempt(k)
					a.Done(i%4 == 0)
				default:
					l.Fail(k)
				}
				if i%500 == 0 {
					l.Bans()
					l.Stats()
					l.Sweep()
					l.Unban(k)
				}
			}
		})
	}
	wg.Wait()
}

func TestAddrPrefix(t *testing.T) {
	tests := []struct {
		in         string
		want       string
		v4, v6     int
		wantErrors bool
	}{
		{in: "203.0.113.7:1234", v4: 32, v6: 64, want: "203.0.113.7/32"},
		{in: "203.0.113.7", v4: 24, v6: 64, want: "203.0.113.0/24"},
		{in: "[2001:db8::1]:443", v4: 32, v6: 64, want: "2001:db8::/64"},
		{in: "[::ffff:203.0.113.7]:443", v4: 32, v6: 64, want: "203.0.113.7/32"},
		{in: "fe80::1%eth0", v4: 32, v6: 200, want: "fe80::1/128"},
		{in: "[fe80::1%eth0]:80", v4: -3, v6: 10, want: "fe80::/10"},
		{in: "10.1.2.3", v4: 99, v6: 0, want: "10.1.2.3/32"},
		{in: "10.1.2.3", v4: -1, v6: 0, want: "0.0.0.0/0"},
		{in: "example.com:80", wantErrors: true},
		{in: "", wantErrors: true},
		{in: "@", wantErrors: true},
	}
	for _, tt := range tests {
		p, err := RemotePrefix(tt.in, tt.v4, tt.v6)
		if tt.wantErrors {
			if !errors.Is(err, ErrInvalidAddr) {
				t.Errorf("RemotePrefix(%q) = %v, %v", tt.in, p, err)
			}
			continue
		}
		if err != nil || p.String() != tt.want {
			t.Errorf("RemotePrefix(%q, %d, %d) = %v, %v, want %s", tt.in, tt.v4, tt.v6, p, err, tt.want)
		}
	}
	if p := AddrPrefix(netip.Addr{}, 32, 64); p.IsValid() {
		t.Error("prefix of the zero Addr")
	}
}

func BenchmarkFail(b *testing.B) {
	l := MustNew[netip.Prefix](Config{Threshold: 1 << 30})
	keys := make([]netip.Prefix, 1024)
	for i := range keys {
		keys[i] = AddrPrefix(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), HostBitsV4, SiteBitsV6)
	}
	b.ReportAllocs()
	var n atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.Fail(keys[n.Add(1)%uint64(len(keys))])
		}
	})
}

func BenchmarkIsBanned(b *testing.B) {
	l := MustNew[string](Config{Threshold: 1})
	l.Fail("banned")
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			l.IsBanned("banned")
			l.IsBanned("other")
		}
	})
}
