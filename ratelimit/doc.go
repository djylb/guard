// Package ratelimit limits events per second with the generic cell rate
// algorithm (GCRA), either for a single state the caller keeps (GCRA) or
// for many string keys (Limiter).
//
// # Algorithm
//
// A Rate gives a sustained rate, Per events per second, and a Burst: the
// number of events that may arrive back to back at a fresh state. The
// state is one number, the theoretical arrival time (tat): the moment at
// which the events admitted so far have drained at the sustained rate.
// With interval = 1s/Per and allowance = (max(Burst,1)-1)*interval, a
// request for n units at time now is handled as follows:
//
//	tat  = max(tat, now)
//	next = tat + n*interval
//	refused when now < next - interval - allowance; the wait is the
//	    difference, and tat is not changed
//	otherwise tat = next
//
// A refused request therefore costs nothing, and a fresh state, whose tat
// is taken to be now, admits Burst single events at once. Penalize charges
// without refusing: tat = max(tat, now) + n*interval. Charging a state
// above its burst makes it refuse until the debt has drained.
//
// The rule is evaluated exactly, in 128 bits, so no combination of rate,
// burst and n can overflow it; times are int64 nanoseconds, and the state
// saturates at the end of that range, some 292 years from the origin.
//
// # Units and edge cases
//
// A Rate with Per <= 0 is unlimited: every request is admitted and no
// state is kept or changed. A Burst below 1 counts as 1. A Per that is NaN
// is invalid and refuses every request, with the longest wait; a Per
// above 1e9 has an interval of less than a nanosecond, which counts as
// zero: such a rate adds no debt, so it admits everything while the key
// holds none, but it does not pay off debt that another rate left. An
// interval too long for an int64 is capped at 2^62 ns.
//
// A request of n units is admitted only when n <= Burst, and then only
// while the state holds at most Burst-n units of debt. A request with
// n > Burst is never admitted, however long it waits: the wait it returns
// is the distance to the first moment that would admit it if the state
// did not drain below its debt, and is not a promise. Split large
// requests, or raise Burst. A request of n = 0 is admitted when the state
// holds no more than Burst units of debt (one unit more than a request of
// one unit tolerates) and changes nothing. A negative n is refused; a
// Penalize with n <= 0 does nothing.
//
// # Token bucket
//
// GCRA is the same limit as a token bucket of Burst tokens, refilled with
// Per tokens per second, from which each event takes one token: a
// request is admitted when at least one whole token is left, and a fresh
// bucket is full. For a whole number of units n the two admit the same
// requests; they differ only where a float64 bucket rounds, within a
// nanosecond of the moment a token becomes available. They differ for a
// bucket whose capacity is not a whole number of tokens: GCRA has no
// fractional capacity, so a caller migrating from such a bucket picks a
// whole Burst, for example by rounding up. A bucket is full exactly when
// the state is Idle.
//
// # Memory and concurrency
//
// A GCRA is 8 bytes, its zero value is a fresh state with a full burst,
// and it is not safe for concurrent use: the caller serialises access and
// evicts the entries it no longer needs, dropping those that are Idle
// without loss.
//
// A Limiter holds GCRA states by key in 64 shards, each locked on its own
// and each an LRU of a fixed share of the capacity. A key that is not
// held is a fresh state; evicting the least recently used key forgets
// only its debt. Memory is bounded by the capacity and reclaimed by the
// calls that use it; there are no goroutines or timers. Allow and
// Penalize do not allocate, refusals included, apart from the calls that
// add a key while the table is still growing towards its capacity: once a
// shard is full, a new key replaces the least recently used one in place.
// The Limiter keeps the key string it is first given, so the caller must
// not modify its bytes afterwards; clone a key that is a substring of a
// large buffer.
//
// Times are passed in as a time.Time. A Limiter measures them from the
// moment it was created, on the monotonic clock if the times carry a
// monotonic reading, so stepping the wall clock does not matter for
// times from time.Now. Times without a monotonic reading follow the wall
// clock. A GCRA takes plain int64 nanoseconds; use a monotonic count.
//
// The zero Limiter, and a nil one, is not usable and refuses every
// request, unlimited rates included.
package ratelimit
