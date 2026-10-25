package replay

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a settable clock without a monotonic reading.
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

func mustNew(t testing.TB, c Config) *Window {
	t.Helper()
	w, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func nonce(i uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], i)
	return b[:]
}

func TestCheck(t *testing.T) {
	clk := newFakeClock()
	w := mustNew(t, Config{Now: clk.Now, Window: time.Minute, Skew: 5 * time.Second, Capacity: 64})
	now := clk.Now()
	if err := w.Check(now, []byte("a")); err != nil {
		t.Fatalf("first check: %v", err)
	}
	if err := w.Check(now, []byte("a")); !errors.Is(err, ErrReplay) {
		t.Fatalf("second check: %v, want ErrReplay", err)
	}
	if err := w.CheckString(now.Add(time.Second), "a"); !errors.Is(err, ErrReplay) {
		t.Fatalf("same nonce, other timestamp: %v, want ErrReplay", err)
	}
	if err := w.CheckString(now, "b"); err != nil {
		t.Fatalf("other nonce: %v", err)
	}
	tests := []struct {
		ts   time.Time
		want error
		name string
	}{
		{now.Add(-time.Minute), nil, "oldest accepted"},
		{now.Add(-time.Minute - 1), ErrStale, "too old"},
		{now.Add(5 * time.Second), nil, "newest accepted"},
		{now.Add(5*time.Second + 1), ErrFuture, "too new"},
		{time.Time{}, ErrStale, "zero time"},
		{time.Unix(math.MinInt64/2, 0), ErrStale, "min time"},
		{time.Unix(math.MaxInt64/2, 0), ErrFuture, "max time"},
	}
	for i, tt := range tests {
		if err := w.Check(tt.ts, nonce(uint64(i)+100)); !errors.Is(err, tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, err, tt.want)
		}
	}
	if err := w.Check(now, nil); !errors.Is(err, ErrEmptyNonce) {
		t.Errorf("empty nonce: %v", err)
	}
	if err := w.CheckString(now, ""); !errors.Is(err, ErrEmptyNonce) {
		t.Errorf("empty string nonce: %v", err)
	}
}

func TestRejectedNotRemembered(t *testing.T) {
	clk := newFakeClock()
	w := mustNew(t, Config{Now: clk.Now, Window: time.Minute, Capacity: 8})
	if err := w.Check(clk.Now().Add(time.Hour), []byte("x")); !errors.Is(err, ErrFuture) {
		t.Fatal(err)
	}
	if err := w.Check(clk.Now(), []byte("x")); err != nil {
		t.Fatalf("nonce of a rejected message: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	clk := newFakeClock()
	w := mustNew(t, Config{Now: clk.Now, Window: time.Minute, Skew: 10 * time.Second, Capacity: 4, Shards: 1})
	// A message stamped at the newest acceptable time stays rejected for
	// as long as its timestamp is acceptable.
	ts := clk.Now().Add(10 * time.Second)
	if err := w.Check(ts, []byte("n")); err != nil {
		t.Fatal(err)
	}
	clk.Advance(70 * time.Second) // ts is now exactly Window old: still acceptable
	if err := w.Check(ts, []byte("n")); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay at window edge: %v", err)
	}
	clk.Advance(1)
	if err := w.Check(ts, []byte("n")); !errors.Is(err, ErrStale) {
		t.Fatalf("after window: %v", err)
	}
	// Entries expire in order, so the ring keeps cycling.
	for i := range uint64(100) {
		if err := w.Check(clk.Now(), nonce(i)); err != nil {
			t.Fatal(i, err)
		}
		clk.Advance(30 * time.Second)
	}
	if n := w.Stats().Len; n > 4 {
		t.Fatalf("Len = %d, capacity 4", n)
	}
}

// TestFullNeverAdmitsReplay floods a full window and checks that no
// accepted nonce is accepted again while its timestamp is acceptable.
func TestFullNeverAdmitsReplay(t *testing.T) {
	for _, policy := range []FullPolicy{ShrinkWindow, RejectNew} {
		t.Run(policy.String(), func(t *testing.T) {
			clk := newFakeClock()
			w := mustNew(t, Config{Now: clk.Now, Window: time.Minute, Skew: time.Second, Capacity: 16, Shards: 1, Full: policy})
			type msg struct {
				ts time.Time
				n  uint64
			}
			var accepted []msg
			for i := range uint64(200) {
				ts := clk.Now().Add(time.Duration(i%3) * time.Second / 2)
				err := w.Check(ts, nonce(i))
				switch {
				case err == nil:
					accepted = append(accepted, msg{ts, i})
				case policy == RejectNew && errors.Is(err, ErrFull):
				case policy == ShrinkWindow && errors.Is(err, ErrStale):
				default:
					t.Fatalf("check %d: %v", i, err)
				}
				clk.Advance(100 * time.Millisecond)
				for _, m := range accepted {
					if err := w.Check(m.ts, nonce(m.n)); err == nil {
						t.Fatalf("replay of %d accepted", m.n)
					}
				}
			}
			if policy == RejectNew && len(accepted) != 16 {
				t.Fatalf("accepted %d, want 16", len(accepted))
			}
			if policy == ShrinkWindow && len(accepted) < 100 {
				t.Fatalf("accepted only %d", len(accepted))
			}
		})
	}
}

func TestShrinkWindowKeepsFreshTraffic(t *testing.T) {
	clk := newFakeClock()
	w := mustNew(t, Config{Now: clk.Now, Window: time.Minute, Capacity: 4, Shards: 1})
	for i := range uint64(4) {
		if err := w.Check(clk.Now(), nonce(i)); err != nil {
			t.Fatal(err)
		}
	}
	clk.Advance(time.Millisecond)
	if err := w.Check(clk.Now(), nonce(10)); err != nil {
		t.Fatalf("fresh message on a full window: %v", err)
	}
	if err := w.Check(clk.Now().Add(-time.Millisecond), nonce(11)); !errors.Is(err, ErrStale) {
		t.Fatalf("message at the evicted timestamp: %v, want ErrStale", err)
	}
}

func TestWallClockStepBack(t *testing.T) {
	clk := newFakeClock()
	w := mustNew(t, Config{Now: clk.Now, Window: time.Minute, Capacity: 8, Shards: 1})
	ts := clk.Now()
	if err := w.Check(ts, []byte("n")); err != nil {
		t.Fatal(err)
	}
	clk.Advance(2 * time.Minute)
	// A fresh check forgets n and raises the floor to its timestamp.
	if err := w.Check(clk.Now(), []byte("m")); err != nil {
		t.Fatal(err)
	}
	clk.Advance(-2 * time.Minute) // the wall clock is stepped back
	if err := w.Check(ts, []byte("n")); err == nil {
		t.Fatal("forgotten nonce accepted after the clock stepped back")
	}
}

func TestMonotonicExpiry(t *testing.T) {
	// With the real clock, entries are kept on the monotonic clock.
	w := mustNew(t, Config{Window: time.Hour, Capacity: 8})
	now := time.Now()
	if err := w.Check(now, []byte("n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Check(now, []byte("n")); !errors.Is(err, ErrReplay) {
		t.Fatal(err)
	}
}

func TestConfig(t *testing.T) {
	bad := []Config{
		{},
		{Window: -1},
		{Window: time.Second, Skew: -1},
		{Window: time.Second, Capacity: -1},
		{Window: time.Second, Shards: -1},
		{Window: time.Second, Full: FullPolicy(9)},
	}
	for _, c := range bad {
		if _, err := New(c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("New(%+v) = %v, want ErrInvalidConfig", c, err)
		}
	}
	tests := []struct {
		capacity, shards int
		wantCap          int
		wantShards       int
	}{
		{1, 0, 1, 1},
		{3, 8, 4, 2},
		{10, 3, 12, 4},
		{0, 1, DefaultCapacity, 1},
	}
	for _, tt := range tests {
		w := mustNew(t, Config{Window: time.Second, Capacity: tt.capacity, Shards: tt.shards})
		if c := w.Stats().Capacity; c != tt.wantCap || len(w.shards) != tt.wantShards {
			t.Errorf("capacity %d shards %d: got %d/%d, want %d/%d", tt.capacity, tt.shards,
				c, len(w.shards), tt.wantCap, tt.wantShards)
		}
	}
	if FullPolicy(7).String() != "FullPolicy(7)" {
		t.Error(FullPolicy(7).String())
	}
}

func TestUninitialized(t *testing.T) {
	// A nil and a zero Window both fail closed.
	for _, w := range []*Window{nil, new(Window)} {
		if err := w.Check(time.Now(), []byte("n")); !errors.Is(err, ErrUninitialized) {
			t.Error(err)
		}
		if err := w.CheckString(time.Now(), "n"); !errors.Is(err, ErrUninitialized) {
			t.Error(err)
		}
		if w.Stats() != (Stats{}) {
			t.Error("nil or zero window reports entries")
		}
	}
}

func TestConcurrent(t *testing.T) {
	w := mustNew(t, Config{Window: time.Minute, Capacity: 1 << 14})
	const goroutines, per = 8, 1000
	var accepted atomic.Int64
	var wg sync.WaitGroup
	now := time.Now()
	for range goroutines {
		wg.Go(func() {
			for i := range uint64(per) {
				if w.Check(now, nonce(i)) == nil {
					accepted.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if accepted.Load() != per {
		t.Fatalf("accepted %d distinct nonces, want %d", accepted.Load(), per)
	}
}

func TestCheckAllocs(t *testing.T) {
	clk := newFakeClock()
	w := mustNew(t, Config{Now: clk.Now, Window: time.Second, Capacity: 1024, Shards: 4})
	var i uint64
	b := make([]byte, 8)
	check := func() {
		i++
		binary.BigEndian.PutUint64(b, i)
		clk.Advance(10 * time.Millisecond)
		if err := w.Check(clk.Now(), b); err != nil {
			t.Fatal(err)
		}
	}
	for range 5000 {
		check() // reach steady state: the ring has cycled
	}
	if n := testing.AllocsPerRun(1000, check); n != 0 {
		t.Fatalf("Check allocates %v times", n)
	}
}

func BenchmarkCheck(b *testing.B) {
	w := mustNew(b, Config{Window: time.Second, Capacity: 1 << 16})
	var ctr atomic.Uint64
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, 16)
		for pb.Next() {
			binary.BigEndian.PutUint64(buf, ctr.Add(1))
			_ = w.Check(time.Now(), buf)
		}
	})
}

func BenchmarkCheckReplay(b *testing.B) {
	w := mustNew(b, Config{Window: time.Hour})
	n := []byte("0123456789abcdef")
	now := time.Now()
	_ = w.Check(now, n)
	b.ReportAllocs()
	for b.Loop() {
		_ = w.Check(now, n)
	}
}

func TestGrowth(t *testing.T) {
	clk := newFakeClock()
	w := mustNew(t, Config{Now: clk.Now, Window: time.Minute, Capacity: 100, Shards: 1, Full: RejectNew})
	if len(w.shards[0].ring) >= 100 {
		t.Fatal("ring allocated in full up front")
	}
	// Expire some entries so that the ring has wrapped when it grows.
	for i := range uint64(10) {
		if err := w.Check(clk.Now(), nonce(i)); err != nil {
			t.Fatal(err)
		}
	}
	clk.Advance(time.Minute + time.Nanosecond)
	for i := uint64(100); i < 200; i++ {
		if err := w.Check(clk.Now(), nonce(i)); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := w.Check(clk.Now(), nonce(1000)); !errors.Is(err, ErrFull) {
		t.Fatalf("beyond capacity: %v", err)
	}
	for i := uint64(100); i < 200; i++ {
		if err := w.Check(clk.Now(), nonce(i)); !errors.Is(err, ErrReplay) {
			t.Fatalf("nonce %d after growth: %v", i, err)
		}
	}
}

func TestDefaultMemory(t *testing.T) {
	var a, b runtime.MemStats
	runtime.ReadMemStats(&a)
	w := mustNew(t, Config{Window: time.Minute})
	runtime.ReadMemStats(&b)
	if kib := (b.TotalAlloc - a.TotalAlloc) / 1024; kib > 512 {
		t.Fatalf("a new default Window allocates %d KiB", kib)
	}
	runtime.KeepAlive(w)
}

func TestStatsEvicted(t *testing.T) {
	clk := newFakeClock()
	w := mustNew(t, Config{Now: clk.Now, Window: time.Hour, Capacity: 2, Shards: 1})
	for i := range uint64(5) {
		clk.Advance(time.Millisecond)
		if err := w.Check(clk.Now(), nonce(i)); err != nil {
			t.Fatal(i, err)
		}
	}
	if st := w.Stats(); st != (Stats{Len: 2, Capacity: 2, Evicted: 3}) {
		t.Fatalf("Stats = %+v", st)
	}
}

func TestConfigJSON(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"window":"30s","skew":"5s","capacity":4096,"shards":2,"full":"rejectnew"}`), &c); err != nil {
		t.Fatal(err)
	}
	want := Config{Window: 30 * time.Second, Skew: 5 * time.Second, Capacity: 4096, Shards: 2, Full: RejectNew}
	if c.Now != nil || c.Window != want.Window || c.Skew != want.Skew || c.Capacity != want.Capacity ||
		c.Shards != want.Shards || c.Full != want.Full {
		t.Fatalf("got %+v", c)
	}
	// Absent fields keep their value.
	if err := json.Unmarshal([]byte(`{"skew":"1s"}`), &c); err != nil || c.Window != want.Window || c.Skew != time.Second {
		t.Fatalf("partial: %v %+v", err, c)
	}
	for _, bad := range []string{`{"window":30}`, `{"window":"x"}`, `{"full":"Drop"}`, `{"windw":"1s"}`, `{"full":1}`, `[]`} {
		if err := json.Unmarshal([]byte(bad), &c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	for _, p := range []FullPolicy{ShrinkWindow, RejectNew} {
		if q, err := ParseFullPolicy(p.String()); err != nil || q != p {
			t.Errorf("ParseFullPolicy(%v) = %v, %v", p, q, err)
		}
	}
}
