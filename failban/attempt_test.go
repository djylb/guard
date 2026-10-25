package failban

import (
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestAttemptConcurrentSlowChecks starts many concurrent slow checks of
// one key: no more than Threshold may run, and all failing bans the key.
func TestAttemptConcurrentSlowChecks(t *testing.T) {
	l := mustNew[string](t, Config{Threshold: 5})
	var checked, running, peak atomic.Int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() {
			<-start
			a := l.Attempt("admin")
			if !a.Allowed() {
				a.Release()
				return
			}
			checked.Add(1)
			n := running.Add(1)
			for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
			}
			time.Sleep(10 * time.Millisecond) // a slow password hash
			running.Add(-1)
			a.Fail()
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

func TestAttemptReleaseKeepsFailures(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 3})
	l.Fail("u")
	l.Fail("u")
	// Two failures: one attempt may run.
	a := l.Attempt("u")
	if !a.Allowed() || a.RetryAfter() != 0 {
		t.Fatal("attempt refused below Threshold")
	}
	if b := l.Attempt("u"); b.Allowed() {
		t.Fatal("Threshold attempts in flight, yet another was allowed")
	} else if b.RetryAfter() != time.Second {
		t.Fatalf("refused for in-flight attempts: RetryAfter %v", b.RetryAfter())
	}
	a.Release()
	// The release kept the failures.
	if l.Failures("u") != 2 {
		t.Fatalf("Failures = %d", l.Failures("u"))
	}
	if r := a.Fail(); r != (Result{}) {
		t.Fatalf("a second settlement counted: %+v", r)
	}
	b := l.Attempt("u")
	r := b.Fail()
	if !r.Banned || !r.Started || r.Offences != 1 || !r.Until.Equal(clk.Now().Add(DefaultBanDuration)) {
		t.Fatalf("Fail at Threshold = %+v", r)
	}
	clk.Advance(time.Minute + 500*time.Millisecond)
	c := l.Attempt("u")
	if c.Allowed() || c.RetryAfter() != DefaultBanDuration-time.Minute {
		t.Fatalf("attempt of a banned key: %v %v", c.Allowed(), c.RetryAfter())
	}
	if r := c.Fail(); r != (Result{}) {
		t.Fatalf("Fail of a refused attempt counted: %+v", r)
	}
	if r := l.Fail("u"); !r.Banned || r.Started || r.Offences != 1 {
		t.Fatalf("Fail of a banned key = %+v", r)
	}
	if st := l.Stats(); st.Failures != 3 || st.Started != 1 || st.Refused != 2 {
		t.Fatalf("Stats = %+v", st)
	}
}

// TestAttemptRefusedAtStart is a regression test: an attempt refused at
// the Limiter's first instant, when its clock reads zero, is refused.
func TestAttemptRefusedAtStart(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 1})
	a := l.Attempt("u")
	if b := l.Attempt("u"); b.Allowed() {
		t.Fatal("second attempt allowed with Threshold 1 in flight")
	}
	a.Release()
}

func TestAttemptSucceed(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 3})
	l.Fail("u")
	a := l.Attempt("u")
	a.Succeed()
	if l.Failures("u") != 0 || l.Stats().Pending != 0 {
		t.Fatalf("Succeed kept failures: %d, %+v", l.Failures("u"), l.Stats())
	}
	a.Release() // a second settlement does nothing
	b := l.Attempt("u")
	if !b.Allowed() {
		t.Fatal("refused after Succeed")
	}
	b.Release()
}

func TestRetryAfterRounding(t *testing.T) {
	for _, tt := range []struct{ retry, want time.Duration }{
		{0, time.Second},
		{time.Millisecond, time.Second},
		{time.Second, time.Second},
		{time.Second + 1, 2 * time.Second},
		{math.MaxInt64, math.MaxInt64},
	} {
		a := Attempt[string]{retry: tt.retry}
		if got := a.RetryAfter(); got != tt.want {
			t.Errorf("RetryAfter of %v = %v, want %v", tt.retry, got, tt.want)
		}
	}
}

func TestAttemptCounterGone(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 2, MaxPending: 2, MaxBans: 4, Shards: 1})
	a := l.Attempt("u")
	l.Unban("u") // drops the counter, and the reservation, of u
	l.Fail("u")
	if !a.Fail().Banned {
		t.Fatal("failure of a reservation whose counter was dropped not counted")
	}
	// An evicted counter takes its reservations along.
	b := l.Attempt("v")
	l.Fail("w")
	l.Fail("x") // evicts v
	if l.Failures("v") != 0 {
		t.Fatal("v not evicted")
	}
	b.Release()
	if l.Failures("v") != 0 {
		t.Fatal("Release after eviction counted")
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
	c.Release()
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
	a.Release()
}

// TestEvictionKeepsEscalation checks that a ban ended early by
// EvictSoonest leaves the key one failure from a longer ban.
func TestEvictionKeepsEscalation(t *testing.T) {
	clk := newFakeClock()
	l := newTest(t, clk, Config{Threshold: 3, BanDuration: time.Minute, MaxBanDuration: time.Hour,
		MaxPending: 16, MaxBans: 1, Shards: 1, Full: EvictSoonest})
	failN(l, "admin", 3)
	clk.Advance(time.Minute)
	failN(l, "admin", 3) // second offence: two minutes
	clk.Advance(time.Second)
	failN(l, "junk", 3) // evicts admin's ban
	if l.IsBanned("admin") {
		t.Fatal("ban not evicted")
	}
	until, banned := ub(l.Fail("admin"))
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
		failN(users, string('a'+rune(j)), 5)
	}
	if !users.IsBanned("admin") {
		t.Fatalf("admin's ban lifted by made-up names: %+v", users.Stats())
	}
}

func TestZeroLimiter(t *testing.T) {
	// A nil and a zero Limiter both fail closed.
	for _, l := range []*Limiter[string]{nil, new(Limiter[string])} {
		if !l.IsBanned("x") {
			t.Error("zero Limiter does not fail closed")
		}
		if !l.Fail("x").Banned {
			t.Error("zero Limiter Fail")
		}
		a := l.Attempt("x")
		if a.Allowed() || a.RetryAfter() != time.Second {
			t.Error("zero Limiter allowed an attempt")
		}
		a.Fail()
		a.Succeed()
		l.Succeed("x")
		l.Sweep()
		l.Reset()
		if !errors.Is(l.Ban(Ban[string]{Key: "x", Until: time.Now().Add(time.Hour)}), ErrUninitialized) {
			t.Error("zero Limiter accepted a ban")
		}
		if l.Unban("x") || l.Failures("x") != 0 || l.Bans() != nil || l.Stats() != (Stats{}) {
			t.Error("zero Limiter reports state")
		}
	}
}

func BenchmarkAttempt(b *testing.B) {
	l := mustNew[string](b, Config{Threshold: 1 << 30})
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			a := l.Attempt("user")
			a.Release()
		}
	})
}
