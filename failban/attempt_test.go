package failban

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAttemptConcurrentSlowChecks starts many concurrent slow checks of
// one key: no more than Threshold may run, and all failing bans the key.
func TestAttemptConcurrentSlowChecks(t *testing.T) {
	l := MustNew[string](Config{Threshold: 5})
	var checked, running, peak atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() {
			<-start
			a := l.Attempt("admin")
			if !a.Allowed() {
				a.Done(true)
				return
			}
			checked.Add(1)
			n := running.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(10 * time.Millisecond) // a slow password hash
			running.Add(-1)
			a.Done(false)
		})
	}
	close(start)
	wg.Wait()
	if checked.Load() > 5 || peak.Load() > 5 {
		t.Fatalf("Threshold 5, but %d checks ran, %d at once", checked.Load(), peak.Load())
	}
	if !l.IsBanned("admin") {
		t.Fatal("not banned after Threshold failures")
	}
}

func TestAttemptSuccessReleases(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 3})
	l.Fail("u")
	l.Fail("u")
	// Two failures: one attempt may run.
	a := l.Attempt("u")
	if !a.Allowed() || !a.Until().IsZero() {
		t.Fatal("attempt refused below Threshold")
	}
	if b := l.Attempt("u"); b.Allowed() {
		t.Fatal("Threshold attempts in flight, yet another was allowed")
	} else if !b.Until().IsZero() {
		t.Fatal("refused for in-flight attempts, yet reported a ban end")
	}
	if _, banned := a.Done(true); banned {
		t.Fatal("success banned")
	}
	// The success released the reservation but kept the failures.
	if l.Failures("u") != 2 {
		t.Fatalf("Failures = %d", l.Failures("u"))
	}
	if _, banned := a.Done(false); banned {
		t.Fatal("a second Done counted")
	}
	b := l.Attempt("u")
	until, banned := b.Done(false)
	if !banned || !until.Equal(clk.Now().Add(DefaultBanDuration)) {
		t.Fatalf("Done(false) at Threshold = %v, %v", until, banned)
	}
	c := l.Attempt("u")
	if c.Allowed() || !c.Until().Equal(until) {
		t.Fatalf("attempt of a banned key: %v %v", c.Allowed(), c.Until())
	}
	if _, banned := c.Done(false); banned {
		t.Fatal("Done of a refused attempt counted")
	}
}

func TestAttemptCounterGone(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 2, Capacity: 2, MaxBans: 4, Shards: 1})
	a := l.Attempt("u")
	l.Unban("u") // drops the counter, and the reservation, of u
	l.Fail("u")
	if _, banned := a.Done(false); !banned {
		t.Fatal("failure of a reservation whose counter was dropped not counted")
	}
	// An evicted counter takes its reservations along.
	b := l.Attempt("v")
	l.Fail("w")
	l.Fail("x") // evicts v
	if l.Failures("v") != 0 {
		t.Fatal("v not evicted")
	}
	if _, banned := b.Done(true); banned {
		t.Fatal("Done(true) after eviction")
	}
	// A slow attempt does not lose its reservation to a sweep.
	c := l.Attempt("y")
	clk.Advance(2 * DefaultWindow)
	l.Sweep()
	if d := l.Attempt("y"); !d.Allowed() {
		t.Fatal("second attempt refused below Threshold")
	} else if e := l.Attempt("y"); e.Allowed() {
		t.Fatal("reservation lost to a sweep")
	}
	c.Done(true)
}

func TestSucceedKeepsReservations(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 2})
	l.Fail("u")
	a := l.Attempt("u")
	l.Succeed("u")
	if l.Failures("u") != 0 {
		t.Fatal("Succeed kept failures")
	}
	if b := l.Attempt("u"); !b.Allowed() {
		t.Fatal("refused after Succeed")
	} else if c := l.Attempt("u"); c.Allowed() {
		t.Fatal("Succeed released reservations")
	}
	a.Done(true)
}

// TestEvictionKeepsEscalation checks that a ban ended early by
// EvictSoonest leaves the key one failure from a longer ban.
func TestEvictionKeepsEscalation(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 3, BanDuration: time.Minute, MaxBanDuration: time.Hour,
		Capacity: 16, MaxBans: 1, Shards: 1, Full: EvictSoonest})
	failN(l, "admin", 3)
	clk.Advance(time.Minute)
	failN(l, "admin", 3) // second offence: two minutes
	clk.Advance(time.Second)
	failN(l, "junk", 3) // evicts admin's ban
	if l.IsBanned("admin") {
		t.Fatal("ban not evicted")
	}
	until, banned := l.Fail("admin")
	if !banned || until.Sub(clk.Now()) != 4*time.Minute {
		t.Fatalf("after eviction: %v, %v; want a third, four-minute ban", until.Sub(clk.Now()), banned)
	}
}

// TestNameKeyedDefault is a regression test: made-up names must not lift
// the ban on a targeted account under the default policy.
func TestNameKeyedDefault(t *testing.T) {
	clk := newFakeClock()
	users := newTest(t, clk, Config{Threshold: 5, MaxBanDuration: 24 * time.Hour, MaxBans: 4, Shards: 1})
	failN(users, "admin", 5)
	for j := range 4 {
		clk.Advance(time.Millisecond)
		failN(users, string(rune('a'+j)), 5)
	}
	if !users.IsBanned("admin") {
		t.Fatalf("admin's ban lifted by made-up names: %+v", users.Stats())
	}
}

func TestZeroLimiter(t *testing.T) {
	var l Limiter[string]
	if !l.IsBanned("x") {
		t.Error("zero Limiter does not fail closed")
	}
	if _, banned := l.Fail("x"); !banned {
		t.Error("zero Limiter Fail")
	}
	a := l.Attempt("x")
	if a.Allowed() {
		t.Error("zero Limiter allowed an attempt")
	}
	a.Done(false)
	l.Succeed("x")
	l.Sweep()
	l.Reset()
	if l.Unban("x") || l.Failures("x") != 0 || l.Bans() != nil || l.Stats() != (Stats{}) {
		t.Error("zero Limiter reports state")
	}
	var nilL *Limiter[string]
	na := nilL.Attempt("x")
	if !nilL.IsBanned("x") || na.Allowed() {
		t.Error("nil Limiter does not fail closed")
	}
}

func BenchmarkAttempt(b *testing.B) {
	l := MustNew[string](Config{Threshold: 1 << 30})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			a := l.Attempt("user")
			a.Done(true)
		}
	})
}
