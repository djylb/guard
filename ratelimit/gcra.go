package ratelimit

import (
	"math"
	"math/bits"
	"time"

	"github.com/djylb/guard/internal/num"
)

// Rate is a limit: Per events per second, with Burst events admitted back
// to back by a fresh state. Per <= 0 means unlimited; a Burst below 1
// counts as 1. See the package documentation for the exact semantics.
type Rate struct {
	// Per is the sustained rate in events per second.
	Per float64
	// Burst is the number of single events admitted at once by a fresh
	// state, and the largest n a request may carry.
	Burst int
}

const (
	maxInterval = int64(1) << 62
	forever     = time.Duration(math.MaxInt64)
	// signBit maps the stored word to tat and back, so that the zero
	// word is the earliest tat, a fresh state.
	signBit = uint64(1) << 63
)

type rateKind uint8

const (
	rateLimited rateKind = iota
	rateUnlimited
	rateInvalid
)

// limit returns the interval between events in nanoseconds, 1s/Per
// truncated to a nanosecond, and the burst, at least 1.
func (r Rate) limit() (interval, burst int64, kind rateKind) {
	switch {
	case math.IsNaN(r.Per):
		return 0, 0, rateInvalid
	case r.Per <= 0:
		return 0, 0, rateUnlimited
	}
	f := float64(time.Second) / r.Per
	if f >= float64(maxInterval) {
		interval = maxInterval
	} else {
		interval = int64(f) // 0 for a rate above 1e9
	}
	return interval, int64(max(r.Burst, 1)), rateLimited
}

// GCRA is the state of one limit: the theoretical arrival time. The zero
// value is a fresh state with a full burst. It is not safe for concurrent
// use, and the Rate may differ from call to call: the state holds time,
// not tokens.
type GCRA struct {
	word uint64 // tat in nanoseconds, offset so that the zero value is the earliest tat
}

func (g *GCRA) tat() int64 {
	return int64(g.word ^ signBit) //nolint:gosec // G115: the bits are the two's complement form wanted
}

func (g *GCRA) setTat(t int64) {
	g.word = uint64(t) ^ signBit //nolint:gosec // G115: as in tat
}

// Allow takes n units at now, a time in nanoseconds from any origin that
// never runs backwards for this state, such as a monotonic count. It
// reports whether they are admitted; if not, wait is the time until they
// would be, which is no promise for n > r.Burst (see the package
// documentation) and is the longest duration for an invalid rate. A
// refusal leaves the state unchanged. An unlimited rate admits everything
// and keeps nothing. A negative n is refused.
func (g *GCRA) Allow(now int64, r Rate, n int) (ok bool, wait time.Duration) {
	interval, burst, kind := r.limit()
	switch {
	case kind == rateUnlimited:
		return n >= 0, 0
	case kind == rateInvalid:
		return false, forever
	case n < 0:
		return false, 0
	}
	return g.take(now, interval, burst, n)
}

// take is Allow for a limited rate and n >= 0, with the Rate's limit. The
// request is admitted when the debt, max(tat,now)-now, plus n*interval
// does not exceed burst*interval, which is the rule of the package
// documentation; it is computed in 128 bits so that no input overflows.
func (g *GCRA) take(now, interval, burst int64, n int) (ok bool, wait time.Duration) {
	tat := max(g.tat(), now)
	// n, interval and burst are not negative here, and tat >= now, so the
	// conversions keep their values and the difference is exact modulo 2^64.
	debt := uint64(tat) - uint64(now)                 //nolint:gosec // G115: see above
	hi, lo := bits.Mul64(uint64(n), uint64(interval)) //nolint:gosec // G115: see above
	lo, carry := bits.Add64(lo, debt, 0)
	hi += carry
	capHi, capLo := bits.Mul64(uint64(burst), uint64(interval)) //nolint:gosec // G115: see above
	if hi > capHi || hi == capHi && lo > capLo {
		over, borrow := bits.Sub64(lo, capLo, 0)
		if hi-capHi-borrow != 0 || over > math.MaxInt64 {
			return false, forever
		}
		return false, time.Duration(over)
	}
	g.setTat(num.SatAdd(tat, num.SatMul(int64(n), interval)))
	return true, 0
}

// Penalize charges n units at now without refusing, so that the state
// then holds the debt. It does nothing for an unlimited or invalid rate or
// for n <= 0.
func (g *GCRA) Penalize(now int64, r Rate, n int) {
	interval, _, kind := r.limit()
	if kind != rateLimited || n <= 0 {
		return
	}
	g.charge(now, interval, n)
}

// charge is Penalize for a limited rate and n > 0.
func (g *GCRA) charge(now, interval int64, n int) {
	g.setTat(num.SatAdd(max(g.tat(), now), num.SatMul(int64(n), interval)))
}

// Idle reports whether the state holds no debt at now, that is, whether it
// behaves exactly like a fresh one for every rate and every later time.
// A token bucket in the same state is full. A caller that keeps states in
// its own table may drop an Idle entry without loss.
func (g *GCRA) Idle(now int64) bool {
	return g.tat() <= now
}
