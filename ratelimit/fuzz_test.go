package ratelimit

import (
	"math"
	"testing"
	"time"
)

// FuzzAllow decodes a random sequence of Allow and Penalize calls on a few
// keys, with time moving only forward, and checks the invariants of the
// limit: refusals change nothing and carry a wait, admissions carry none,
// a key never gets more than its burst plus what the rate refills, and a
// Limiter answers as a bare GCRA does.
func FuzzAllow(f *testing.F) {
	f.Add([]byte{3, 9, 0, 1, 0, 1, 1, 0, 0, 2, 1, 1, 7, 255, 0, 3, 40})
	f.Add([]byte{0, 0, 1, 1, 1, 1, 1, 1})
	f.Add([]byte{200, 255, 0, 255, 255, 1, 255, 255})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 2 {
			return
		}
		pers := []float64{0.5, 1, 3, 10, 100, 1000, 1e6, 3e9}
		r := Rate{Per: pers[int(data[0])%len(pers)], Burst: int(data[1]%16) - 1}
		data = data[2:]
		interval := int64(float64(time.Second) / r.Per)
		burst := int64(max(r.Burst, 1))
		l := mustNew(t, Config{Capacity: 6400}) // no eviction among four keys, almost surely
		var gcra [4]GCRA
		var seen [4]bool
		var first [4]int64
		var admitted [4]int64 // units
		now := int64(0)
		for len(data) >= 4 {
			op, k, n, dt := data[0], int(data[1]%4), int(data[2]%24), int64(data[3])
			data = data[4:]
			now += dt * dt * int64(time.Microsecond) // up to 65 ms, many steps small
			at := l.origin.Add(time.Duration(now))
			key := string(rune('a' + k))
			if !seen[k] {
				seen[k], first[k] = true, now
			}
			if op%3 == 0 {
				l.Penalize(key, r, n, at)
				gcra[k].Penalize(now, r, n)
				continue
			}
			before := gcra[k]
			ok, wait := l.Allow(key, r, n, at)
			gok, gwait := gcra[k].Allow(now, r, n)
			if ok != gok || wait != gwait {
				t.Fatalf("Limiter %v, %v; GCRA %v, %v", ok, wait, gok, gwait)
			}
			switch {
			case ok && wait != 0:
				t.Fatalf("admitted with wait %v", wait)
			case !ok && wait <= 0:
				t.Fatalf("refused with wait %v", wait)
			case !ok && gcra[k] != before:
				t.Fatal("a refusal changed the state")
			case !ok && int64(n) <= burst:
				// A request within the burst is admitted once its wait has passed.
				probe := before
				if again, _ := probe.Allow(now+int64(wait), r, n); !again {
					t.Fatalf("n=%d refused again after its wait %v", n, wait)
				}
			}
			if ok {
				admitted[k] += int64(n)
				// Units admitted so far, from a fresh state at first[k], never
				// exceed the burst plus the refill since then.
				if elapsed := now - first[k]; admitted[k]*interval > elapsed+burst*interval {
					t.Fatalf("key %d: %d units in %dns exceed burst %d at interval %d", k, admitted[k], elapsed, burst, interval)
				}
			}
			if gcra[k].Idle(now) && !gcra[k].Idle(math.MaxInt64) {
				t.Fatal("Idle is not monotone")
			}
		}
	})
}
