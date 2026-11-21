package ratelimit

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/guard/internal/race"
)

// refLimiter is the limit written out plainly on time.Time and
// time.Duration, one map entry per key: the behaviour Limiter must keep.
type refLimiter struct{ tat map[string]time.Time }

func newRef() *refLimiter { return &refLimiter{tat: map[string]time.Time{}} }

func (l *refLimiter) entry(key string, now time.Time) time.Time {
	if t, ok := l.tat[key]; ok {
		return t
	}
	l.tat[key] = now
	return now
}

func (l *refLimiter) allow(key string, r Rate, n int, now time.Time) (bool, time.Duration) {
	if r.Per <= 0 {
		return true, 0
	}
	interval := time.Duration(float64(time.Second) / r.Per)
	burst := time.Duration(max(r.Burst, 1)-1) * interval
	tat := l.entry(key, now)
	if tat.Before(now) {
		tat = now
	}
	next := tat.Add(time.Duration(n) * interval)
	if allowAt := next.Add(-interval - burst); now.Before(allowAt) {
		return false, allowAt.Sub(now)
	}
	l.tat[key] = next
	return true, 0
}

func (l *refLimiter) penalize(key string, r Rate, n int, now time.Time) {
	if r.Per <= 0 {
		return
	}
	interval := time.Duration(float64(time.Second) / r.Per)
	tat := l.entry(key, now)
	if tat.Before(now) {
		tat = now
	}
	l.tat[key] = tat.Add(time.Duration(n) * interval)
}

// newRNG returns a reproducible random sequence.
func newRNG(a, b uint64) *rand.Rand {
	return rand.New(rand.NewPCG(a, b)) //nolint:gosec // G404: a reproducible sequence is the point
}

func mustNew(tb testing.TB, c Config) *Limiter {
	tb.Helper()
	l, err := New(c)
	if err != nil {
		tb.Fatal(err)
	}
	return l
}

func TestAllowSequence(t *testing.T) {
	var g GCRA
	r := Rate{Per: 10, Burst: 3} // 100ms interval
	const ms = int64(time.Millisecond)
	steps := []struct {
		now  int64
		n    int
		ok   bool
		wait time.Duration
	}{
		{0, 1, true, 0},
		{0, 1, true, 0},
		{0, 1, true, 0},
		{0, 1, false, 100 * time.Millisecond},
		{40 * ms, 1, false, 60 * time.Millisecond}, // a refusal costs nothing
		{100 * ms, 1, true, 0},
		{100 * ms, 1, false, 100 * time.Millisecond},
		{10_000 * ms, 3, true, 0}, // fully refilled
		{10_000 * ms, 1, false, 100 * time.Millisecond},
	}
	for i, s := range steps {
		ok, wait := g.Allow(s.now, r, s.n)
		if ok != s.ok || wait != s.wait {
			t.Fatalf("step %d: Allow = %v, %v; want %v, %v", i, ok, wait, s.ok, s.wait)
		}
	}
}

func TestEdgeCases(t *testing.T) {
	const ms = int64(time.Millisecond)
	for _, tt := range []struct {
		name string
		r    Rate
		prep int // units charged at time 0 before
		n    int
		now  int64
		ok   bool
		wait time.Duration
	}{
		{"zero rate", Rate{}, 0, 5, 0, true, 0},
		{"negative rate", Rate{Per: -3, Burst: 1}, 0, 1 << 30, 0, true, 0},
		{"infinite rate", Rate{Per: math.Inf(1), Burst: 1}, 0, 9, 0, true, 0},
		{"faster than a nanosecond", Rate{Per: 2e9, Burst: 1}, 0, 9, 0, true, 0},
		{"NaN rate", Rate{Per: math.NaN(), Burst: 1}, 0, 1, 0, false, forever},
		{"burst zero is one", Rate{Per: 10, Burst: 0}, 1, 1, 0, false, 100 * time.Millisecond},
		{"burst negative is one", Rate{Per: 10, Burst: -5}, 0, 1, 0, true, 0},
		{"burst of one admits one", Rate{Per: 10, Burst: 1}, 0, 1, 0, true, 0},
		{"n zero within burst", Rate{Per: 10, Burst: 2}, 2, 0, 0, true, 0},
		{"n zero beyond burst", Rate{Per: 10, Burst: 2}, 3, 0, 0, false, 100 * time.Millisecond},
		{"n zero tolerates one unit more than n one", Rate{Per: 10, Burst: 1}, 1, 0, 0, true, 0},
		{"n equals burst", Rate{Per: 10, Burst: 4}, 0, 4, 0, true, 0},
		{"n equals burst, debt", Rate{Per: 10, Burst: 4}, 1, 4, 0, false, 100 * time.Millisecond},
		{"n beyond burst", Rate{Per: 10, Burst: 2}, 0, 3, 0, false, 100 * time.Millisecond},
		{"n beyond burst stays refused", Rate{Per: 10, Burst: 2}, 0, 3, 5_000 * ms, false, 100 * time.Millisecond},
		{"negative n", Rate{Per: 10, Burst: 2}, 0, -1, 0, false, 0},
		{"debt drains", Rate{Per: 10, Burst: 1}, 1, 1, 100 * ms, true, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var g GCRA
			g.Penalize(0, tt.r, tt.prep)
			ok, wait := g.Allow(tt.now, tt.r, tt.n)
			if ok != tt.ok || wait != tt.wait {
				t.Fatalf("Allow = %v, %v; want %v, %v", ok, wait, tt.ok, tt.wait)
			}
			l := mustNew(t, Config{})
			base := l.origin
			l.Penalize("k", tt.r, tt.prep, base)
			ok, wait = l.Allow("k", tt.r, tt.n, base.Add(time.Duration(tt.now)))
			if ok != tt.ok || wait != tt.wait {
				t.Fatalf("Limiter.Allow = %v, %v; want %v, %v", ok, wait, tt.ok, tt.wait)
			}
		})
	}
}

func TestHugeN(t *testing.T) {
	var g GCRA
	// An interval of 2^62 ns and four units need 2^64 ns, beyond what a
	// Duration holds.
	ok, wait := g.Allow(0, Rate{Per: 1e-300, Burst: 1}, 4)
	if ok || wait != forever || g != (GCRA{}) {
		t.Fatalf("Allow = %v, %v", ok, wait)
	}
	if ok, wait = g.Allow(0, Rate{Per: 1e-300, Burst: 1}, 1); !ok || wait != 0 {
		t.Fatalf("Allow = %v, %v", ok, wait)
	}
	if ok, wait = g.Allow(0, Rate{Per: 1e-300, Burst: 1}, 1); ok || wait != time.Duration(maxInterval) {
		t.Fatalf("Allow = %v, %v", ok, wait)
	}
}

func TestUnlimitedKeepsNoState(t *testing.T) {
	l := mustNew(t, Config{})
	now := time.Now()
	for _, r := range []Rate{{}, {Per: -1}, {Per: math.NaN()}} {
		l.Allow("k", r, 1, now)
		l.Penalize("k", r, 1, now)
	}
	if l.Len() != 0 {
		t.Fatalf("Len = %d", l.Len())
	}
	var g GCRA
	g.Penalize(5, Rate{}, 100)
	g.Penalize(5, Rate{Per: math.NaN()}, 100)
	g.Penalize(5, Rate{Per: 1, Burst: 1}, 0)
	g.Penalize(5, Rate{Per: 1, Burst: 1}, -4)
	if g != (GCRA{}) {
		t.Fatal("state changed")
	}
}

func TestPenalize(t *testing.T) {
	r := Rate{Per: 10, Burst: 2}
	var g GCRA
	g.Penalize(0, r, 5) // five units of debt, above the burst
	if ok, wait := g.Allow(0, r, 1); ok || wait != 400*time.Millisecond {
		t.Fatalf("Allow = %v, %v", ok, wait)
	}
	if g.Idle(400_000_000) || !g.Idle(500_000_000) {
		t.Fatal("Idle")
	}
	if ok, _ := g.Allow(400_000_000, r, 1); !ok {
		t.Fatal("not admitted after the wait")
	}
}

func TestIdle(t *testing.T) {
	var g GCRA
	if !g.Idle(math.MinInt64) || !g.Idle(0) {
		t.Fatal("fresh state is not idle")
	}
	r := Rate{Per: 1, Burst: 1}
	g.Allow(1000, r, 1)
	if g.Idle(1000) || g.Idle(1000+int64(time.Second)-1) || !g.Idle(1000+int64(time.Second)) {
		t.Fatal("Idle boundary")
	}
	// An idle state behaves as a fresh one for another rate and later time.
	var fresh GCRA
	other := Rate{Per: 3, Burst: 5}
	at := 1000 + int64(time.Second)
	for range 8 {
		a, aw := g.Allow(at, other, 1)
		b, bw := fresh.Allow(at, other, 1)
		if a != b || aw != bw {
			t.Fatal("idle state differs from fresh")
		}
	}
}

func TestExtremeTimes(t *testing.T) {
	r := Rate{Per: 1e-300, Burst: math.MaxInt}
	for _, now := range []int64{math.MinInt64, -1, 0, math.MaxInt64 - 1, math.MaxInt64} {
		var g GCRA
		for range 3 {
			g.Allow(now, r, 1)
			g.Penalize(now, r, math.MaxInt)
			g.Allow(now, Rate{Per: 1, Burst: 1}, math.MaxInt)
			g.Idle(now)
		}
	}
	// A zero time.Time is far before the origin and must not panic.
	l := mustNew(t, Config{})
	l.Allow("k", Rate{Per: 1, Burst: 1}, 1, time.Time{})
	l.Allow("k", Rate{Per: 1, Burst: 1}, 1, time.Unix(1<<40, 0))
}

func TestZeroValue(t *testing.T) {
	r := Rate{Per: 1, Burst: 1}
	for _, l := range []*Limiter{nil, {}} {
		for _, rate := range []Rate{r, {}, {Per: math.NaN()}} {
			if ok, _ := l.Allow("k", rate, 1, time.Now()); ok {
				t.Fatalf("zero limiter admitted rate %+v", rate)
			}
		}
		l.Penalize("k", r, 1, time.Now())
		if l.Len() != 0 {
			t.Fatal("Len")
		}
	}
	var g GCRA
	if ok, _ := g.Allow(0, r, 1); !ok {
		t.Fatal("a zero GCRA is a fresh state")
	}
}

func TestNewConfig(t *testing.T) {
	for _, c := range []Config{{Capacity: -1}, {Capacity: MaxCapacity + 1}} {
		if l, err := New(c); !errors.Is(err, ErrInvalidConfig) || l != nil {
			t.Errorf("New(%+v) = %v, %v", c, l, err)
		}
	}
	for _, c := range []Config{{}, {Capacity: 1}, {Capacity: 63}, {Capacity: 64}, {Capacity: 100}, {Capacity: 1 << 20}} {
		l := mustNew(t, c)
		if ok, _ := l.Allow("k", Rate{Per: 1, Burst: 1}, 1, time.Now()); !ok {
			t.Errorf("New(%+v) refuses a fresh key", c)
		}
	}
}

func TestConfigJSON(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"capacity": 1000}`), &c); err != nil || c.Capacity != 1000 {
		t.Fatalf("got %+v, %v", c, err)
	}
	if err := json.Unmarshal([]byte(`{}`), &c); err != nil || c.Capacity != 1000 {
		t.Fatalf("absent field changed the config: %+v, %v", c, err)
	}
	for _, bad := range []string{`{"Capacity":1}`, `{"cap":1}`, `{"capacity":"1"}`, `{"capacity":null}`,
		`{"capacity":1,"capacity":2}`, `[]`, `{"capacity":1.5}`} {
		if err := json.Unmarshal([]byte(bad), &c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", bad, err)
		}
	}
	b, err := json.Marshal(Config{Capacity: 7})
	if err != nil || string(b) != `{"capacity":7}` {
		t.Fatalf("Marshal = %s, %v", b, err)
	}
	var r Rate
	if err := json.Unmarshal([]byte(`{"per": 2.5, "burst": 4}`), &r); err != nil || r != (Rate{Per: 2.5, Burst: 4}) {
		t.Fatalf("got %+v, %v", r, err)
	}
	for _, bad := range []string{`{"rate":1}`, `{"per":null}`, `{"burst":"1"}`, `{"per":1,"per":1}`} {
		if err := json.Unmarshal([]byte(bad), &r); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if b, err := json.Marshal(Rate{Per: 2.5, Burst: 4}); err != nil || string(b) != `{"per":2.5,"burst":4}` {
		t.Fatalf("Marshal = %s, %v", b, err)
	}
}

// randomRate draws a rate whose arithmetic the reference can follow.
func randomRate(rng *rand.Rand) Rate {
	pers := []float64{0, -2, 0.5, 1, 7, 100, 1000, 12345.6, 1e6, 3e9}
	bursts := []int{-1, 0, 1, 2, 5, 50}
	return Rate{Per: pers[rng.IntN(len(pers))], Burst: bursts[rng.IntN(len(bursts))]}
}

// TestDifferentialReference runs random schedules over many keys and
// checks that Limiter answers exactly as the plain reference does.
func TestDifferentialReference(t *testing.T) {
	for seed := range uint64(20) {
		rng := newRNG(seed, 1)
		l := mustNew(t, Config{Capacity: 1 << 16})
		ref := newRef()
		now := l.origin
		for step := range 20000 {
			now = now.Add(time.Duration(rng.Int64N(int64(300 * time.Millisecond))))
			key := "key" + strconv.Itoa(rng.IntN(40))
			r := randomRate(rng)
			n := rng.IntN(8)
			if rng.IntN(4) == 0 {
				l.Penalize(key, r, n, now)
				ref.penalize(key, r, n, now)
				continue
			}
			ok, wait := l.Allow(key, r, n, now)
			rok, rwait := ref.allow(key, r, n, now)
			if ok != rok || wait != rwait {
				t.Fatalf("seed %d step %d: key %s rate %+v n %d: got %v, %v; reference %v, %v", seed, step, key, r, n, ok, wait, rok, rwait)
			}
		}
		if l.Len() != len(ref.tat) {
			t.Fatalf("Len = %d, reference %d", l.Len(), len(ref.tat))
		}
	}
}

// bucket is a float token bucket: capacity burst, refilled at rate tokens
// per second, one token per event, full at the start.
type bucket struct {
	tokens, last float64
}

func (b *bucket) tokensAt(now float64, rate float64, burst int) float64 {
	return math.Min(float64(burst), b.tokens+(now-b.last)*rate/1e9)
}

// TestDifferentialTokenBucket compares GCRA with the token bucket model on
// random schedules. They may differ only where the bucket's float
// arithmetic decides a token that is available exactly now: the
// schedules put many requests at such moments, and the bucket then takes
// GCRA's answer.
func TestDifferentialTokenBucket(t *testing.T) {
	boundary, total := 0, 0
	for seed := range uint64(40) {
		rng := newRNG(seed, 2)
		intervals := []int64{1000, 250_000, 1_000_000, 7_000_000, 333_333_333, 1_000_000_000}
		iv := intervals[rng.IntN(len(intervals))]
		rate := 1e9 / float64(iv)
		r := Rate{Per: rate, Burst: 1 + rng.IntN(12)}
		var g GCRA
		var b bucket
		b.tokens = float64(r.Burst)
		now := rng.Int64N(1 << 40)
		b.last = float64(now)
		for range 20000 {
			switch rng.IntN(3) {
			case 0:
				now += rng.Int64N(3 * iv)
			case 1:
				now += iv // exactly a token
			default:
				now += iv * int64(1+rng.IntN(3)) / int64(1+rng.IntN(3)) // often an exact multiple
			}
			avail := b.tokensAt(float64(now), rate, r.Burst)
			want := avail >= 1
			got, _ := g.Allow(now, r, 1)
			total++
			if got != want {
				if math.Abs(avail-1) > 1e-6 {
					t.Fatalf("seed %d: now %d tokens %v: GCRA %v, bucket %v", seed, now, avail, got, want)
				}
				boundary++
				want = got
			}
			b.tokens, b.last = avail, float64(now)
			if want {
				b.tokens--
			}
		}
	}
	t.Logf("%d of %d decisions were within rounding of a token boundary", boundary, total)
}

func TestIdleIsFullBucket(t *testing.T) {
	r := Rate{Per: 4, Burst: 3}
	var g GCRA
	now := int64(0)
	for range 3 {
		g.Allow(now, r, 1)
	}
	if g.Idle(now) {
		t.Fatal("drained bucket reported idle")
	}
	full := now + 3*int64(250*time.Millisecond)
	if g.Idle(full-1) || !g.Idle(full) {
		t.Fatal("idle exactly when the bucket is full again")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := mustNew(t, Config{})
	r := Rate{Per: 1, Burst: 1}
	now := time.Now()
	if ok, _ := l.Allow("a", r, 1, now); !ok {
		t.Fatal("a")
	}
	if ok, _ := l.Allow("a", r, 1, now); ok {
		t.Fatal("a twice")
	}
	if ok, _ := l.Allow("b", r, 1, now); !ok {
		t.Fatal("b")
	}
	if l.Len() != 2 {
		t.Fatalf("Len = %d", l.Len())
	}
}

func TestEvictionForgetsOnlyDebt(t *testing.T) {
	l := mustNew(t, Config{Capacity: 64}) // one key per shard
	r := Rate{Per: 0.001, Burst: 1}
	now := time.Now()
	const keys = 5000
	for i := range keys {
		l.Allow(strconv.Itoa(i), r, 1, now)
		if n := l.Len(); n > 64 {
			t.Fatalf("Len = %d after %d keys", n, i+1)
		}
	}
	if l.Len() != 64 {
		t.Fatalf("Len = %d", l.Len())
	}
	// Going through the keys the other way round, the newest key of each
	// shard is still held and refused; every older one has been evicted.
	admitted := 0
	for i := keys - 1; i >= 0; i-- {
		if ok, _ := l.Allow(strconv.Itoa(i), r, 1, now); ok {
			admitted++
		}
	}
	if admitted != keys-64 {
		t.Fatalf("admitted %d of %d", admitted, keys)
	}
}

// shardOf builds a bare shard with at most limit keys and a small table,
// so that tests drive the LRU and the hash chains with chosen hashes.
func shardOf(limit, buckets int) *shard {
	return &shard{limit: limit, buckets: make([]int32, buckets), mask: uint64(buckets - 1), //nolint:gosec // G115: buckets is positive
		nodes: make([]node, 1, 2)}
}

func (s *shard) keys() []string {
	var ks []string
	for i := s.head; i != 0; i = s.nodes[i].next {
		ks = append(ks, s.nodes[i].key)
	}
	return ks
}

func TestShardLRUAndChains(t *testing.T) {
	s := shardOf(3, 2)
	// Every hash is 0 or 1 modulo the table, so chains of several nodes form.
	h := map[string]uint64{"a": 0, "b": 2, "c": 4, "d": 6, "e": 1}
	get := func(k string) int32 { return s.get(k, h[k]) }
	check := func(want ...string) {
		t.Helper()
		got := s.keys()
		if fmt.Sprint(got) != fmt.Sprint(want) || len(s.nodes)-1 != len(want) && len(s.nodes)-1 != s.limit {
			t.Fatalf("LRU = %v (%d nodes), want %v", got, len(s.nodes)-1, want)
		}
		for _, k := range want {
			found := false
			for i := s.buckets[h[k]&s.mask]; i != 0; i = s.nodes[i].chain {
				found = found || s.nodes[i].key == k
			}
			if !found {
				t.Fatalf("%q is not in its hash chain", k)
			}
		}
	}
	get("a")
	get("b")
	get("c")
	check("c", "b", "a")
	get("a") // touch the tail
	check("a", "c", "b")
	get("b") // touch the middle... then the head again
	get("b")
	check("b", "a", "c")
	get("d") // evicts c, the least recently used, from the middle of a chain
	check("d", "b", "a")
	if i := get("c"); s.nodes[i].g != (GCRA{}) { // evicts a
		t.Fatal("a reused node is not fresh")
	}
	check("c", "d", "b")
	get("e") // other bucket; evicts b, the chain's tail
	check("e", "c", "d")
	get("a")
	get("b")
	check("b", "a", "e")
	for _, k := range []string{"c", "d"} {
		for i := s.buckets[h[k]&s.mask]; i != 0; i = s.nodes[i].chain {
			if s.nodes[i].key == k {
				t.Fatalf("evicted %q is still chained", k)
			}
		}
	}
	// A shard of one key replaces it every time.
	one := shardOf(1, 1)
	for i := range 10 {
		one.get(strconv.Itoa(i), uint64(i))
		if len(one.keys()) != 1 || one.keys()[0] != strconv.Itoa(i) {
			t.Fatalf("one-key shard holds %v", one.keys())
		}
	}
}

func TestRandomShardAgainstModel(t *testing.T) {
	rng := newRNG(7, 7)
	s := shardOf(8, 4)
	var order []string // most recent first
	for range 20000 {
		k := strconv.Itoa(rng.IntN(20))
		h := uint64(k[0]) * 7 // few distinct hashes: chains form; equal keys hash equally
		s.get(k, h)
		for i, o := range order {
			if o == k {
				order = append(order[:i], order[i+1:]...)
				break
			}
		}
		order = append([]string{k}, order...)
		if len(order) > 8 {
			order = order[:8]
		}
		if fmt.Sprint(s.keys()) != fmt.Sprint(order) {
			t.Fatalf("LRU = %v, want %v", s.keys(), order)
		}
	}
}

func TestConcurrent(t *testing.T) {
	l := mustNew(t, Config{Capacity: 256})
	r := Rate{Per: 1000, Burst: 10}
	base := l.origin
	var wg sync.WaitGroup
	var admitted atomic.Int64
	for w := range 8 {
		wg.Go(func() {
			rng := newRNG(uint64(w), 3) //nolint:gosec // G115: w is a small index
			for i := range 20000 {
				key := strconv.Itoa(rng.IntN(1000))
				now := base.Add(time.Duration(i) * time.Microsecond)
				if i%7 == 0 {
					l.Penalize(key, r, 1, now)
				} else if ok, _ := l.Allow(key, r, 1, now); ok {
					admitted.Add(1)
				}
				if i%1000 == 0 {
					l.Len()
				}
			}
		})
	}
	wg.Wait()
	if n := l.Len(); n > 256 || n == 0 {
		t.Fatalf("Len = %d", n)
	}
}

// TestConcurrentSingleKeyBound checks that goroutines racing on one key
// are admitted no more than the burst and the elapsed time allow.
func TestConcurrentSingleKeyBound(t *testing.T) {
	l := mustNew(t, Config{})
	r := Rate{Per: 100, Burst: 20}
	now := l.origin.Add(time.Hour) // all at the same instant: only the burst
	var wg sync.WaitGroup
	var admitted atomic.Int64
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				if ok, _ := l.Allow("k", r, 1, now); ok {
					admitted.Add(1)
				}
			}
		})
	}
	wg.Wait()
	if admitted.Load() != 20 {
		t.Fatalf("admitted %d, want 20", admitted.Load())
	}
}

func TestAllocs(t *testing.T) {
	if race.Enabled() {
		t.Skip("the race detector changes allocation counts")
	}
	l := mustNew(t, Config{Capacity: 6400}) // 100 keys per shard
	hot := Rate{Per: 1, Burst: 2}
	now := l.origin.Add(time.Second)
	keys := make([]string, 50000)
	for i := range keys {
		keys[i] = "key-" + strconv.Itoa(i)
	}
	for _, k := range keys { // fill every shard and let it cycle
		l.Allow(k, hot, 1, now)
	}
	var g GCRA
	i := 0
	for name, f := range map[string]func(){
		"admit":           func() { l.Allow("hot", Rate{Per: 1e9, Burst: 1 << 20}, 1, now) },
		"refuse":          func() { l.Allow("hot", hot, 1<<20, now) },
		"penalize":        func() { l.Penalize("hot", hot, 1, now) },
		"refuse penalty":  func() { l.Allow("hot", hot, 1, now) },
		"unlimited":       func() { l.Allow("hot", Rate{}, 1, now) },
		"invalid":         func() { l.Allow("hot", Rate{Per: math.NaN()}, 1, now) },
		"evicting churn":  func() { i++; l.Allow(keys[i%len(keys)], hot, 1, now) },
		"evicting charge": func() { i++; l.Penalize(keys[i%len(keys)], hot, 1, now) },
		"Len":             func() { l.Len() },
		"GCRA":            func() { g.Allow(int64(i), hot, 1); g.Penalize(int64(i), hot, 1); g.Idle(0) },
	} {
		if n := testing.AllocsPerRun(2000, f); n != 0 {
			t.Errorf("%s allocates %v times", name, n)
		}
	}
}

func Example() {
	l, err := New(Config{})
	if err != nil {
		panic(err)
	}
	limit := Rate{Per: 2, Burst: 3} // two a second, three at once
	now := time.Now()
	for range 4 {
		ok, wait := l.Allow("203.0.113.7", limit, 1, now)
		fmt.Println(ok, wait)
	}
	// Output:
	// true 0s
	// true 0s
	// true 0s
	// false 500ms
}

func ExampleGCRA() {
	var g GCRA // a fresh state; the caller keeps it in its own table
	limit := Rate{Per: 1, Burst: 1}
	fmt.Println(g.Allow(0, limit, 1))
	fmt.Println(g.Allow(0, limit, 1))
	fmt.Println(g.Idle(int64(time.Second)))
	// Output:
	// true 0s
	// false 1s
	// true
}
