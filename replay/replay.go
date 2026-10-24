// Package replay rejects messages whose nonce was already seen within a
// time window.
//
// A Window remembers the nonces of the messages it accepts. A message
// carries a timestamp and a nonce; Check accepts it once if the timestamp
// lies within the window around the current time and the nonce is new, and
// rejects every later copy:
//
//	w, err := replay.New(replay.Config{Window: 30 * time.Second, Skew: 5 * time.Second})
//	...
//	if err := w.Check(msg.Time, msg.Nonce); err != nil {
//		return err // errors.Is(err, replay.ErrReplay), replay.ErrStale, ...
//	}
//
// The timestamp and nonce must be authenticated by the caller, for example
// covered by a MAC, before Check is called: the window only remembers what
// it is told.
//
// # Memory and the full policy
//
// A Window holds at most Config.Capacity nonces, split evenly across its
// shards. A nonce is remembered for Window+Skew after it is accepted, the
// longest time its timestamp can stay acceptable, and forgotten in the
// order it was accepted, so expiry costs amortised O(1) per check. When a
// shard is full of nonces that are still acceptable, Config.Full decides
// what happens. Neither policy ever accepts a replay:
//
//   - ShrinkWindow, the default, forgets the oldest nonce early and raises
//     the shard's floor to its timestamp: from then on the shard rejects
//     every timestamp at or below the floor as stale. The accepted window
//     shrinks under load instead of reopening.
//   - RejectNew refuses new nonces with ErrFull until an entry expires.
//
// # Clocks
//
// Expiry runs on the monotonic clock, so stepping the wall clock neither
// drops entries early nor keeps them longer. The timestamp check uses the
// wall clock, and each shard's floor also rises to the timestamp of every
// nonce it forgets: a nonce once forgotten stays rejected even if the wall
// clock is stepped back.
//
// Nonces are identified by a 128-bit keyed hash with a per-Window random
// seed, so a check allocates nothing; an attacker cannot choose two nonces
// that collide, and a collision by chance would reject a fresh message,
// never accept a replay. While a nonce is remembered it is rejected with
// any timestamp, so a protocol must not reuse nonces across timestamps.
package replay

import (
	"errors"
	"fmt"
	"hash/maphash"
	"math"
	"math/bits"
	"runtime"
	"sync"
	"time"
)

// Errors returned by Check and CheckString. The rejections are distinct so
// that callers can log or count them; a caller answering a remote peer
// should not reveal which one occurred.
var (
	// ErrReplay reports a nonce that was already accepted.
	ErrReplay = errors.New("replay: nonce already seen")
	// ErrStale reports a timestamp older than the window, or not newer
	// than a shard's floor (see ShrinkWindow).
	ErrStale = errors.New("replay: timestamp too old")
	// ErrFuture reports a timestamp further in the future than the skew
	// allows.
	ErrFuture = errors.New("replay: timestamp too far in the future")
	// ErrFull reports that a RejectNew window has no room for a new nonce.
	ErrFull = errors.New("replay: window full")
	// ErrEmptyNonce reports an empty nonce.
	ErrEmptyNonce = errors.New("replay: empty nonce")
	// ErrUninitialized reports a Window not created by New.
	ErrUninitialized = errors.New("replay: window not created by New")
	// ErrInvalidConfig reports a Config that New cannot use.
	ErrInvalidConfig = errors.New("replay: invalid config")
)

// FullPolicy decides what a Window does when a shard is full of nonces that
// are still acceptable.
type FullPolicy int

const (
	// ShrinkWindow forgets the oldest nonce early and raises the shard's
	// floor so that its timestamp, and every older one, is rejected as
	// stale. Fresh messages keep being accepted while the accepted window
	// shrinks.
	ShrinkWindow FullPolicy = iota
	// RejectNew rejects new nonces with ErrFull until an entry expires.
	RejectNew
)

// String returns the policy's name.
func (p FullPolicy) String() string {
	switch p {
	case ShrinkWindow:
		return "ShrinkWindow"
	case RejectNew:
		return "RejectNew"
	default:
		return fmt.Sprintf("FullPolicy(%d)", int(p))
	}
}

// Default values used for zero Config fields.
const (
	DefaultCapacity = 1 << 16
)

// initialShardSize is the number of entries a shard starts with.
const initialShardSize = 16

// Config configures a Window. Window is required; the other fields have
// defaults.
type Config struct {
	// Now returns the current time. It defaults to time.Now. A clock
	// without a monotonic reading makes expiry follow the wall clock.
	Now func() time.Time
	// Window is how old a timestamp may be. It must be positive.
	Window time.Duration
	// Skew is how far in the future a timestamp may be, to tolerate
	// senders whose clocks run ahead. It must not be negative.
	Skew time.Duration
	// Capacity is the number of nonces remembered at most, rounded up to
	// a multiple of the shard count. It defaults to DefaultCapacity.
	// Memory grows with the nonces remembered, by about 80 bytes each:
	// some 5 MiB at the default capacity. A login form, which sees far
	// fewer messages, can use a few thousand.
	Capacity int
	// Shards is the number of independently locked shards, rounded up to
	// a power of two and lowered so that each shard holds at least one
	// nonce. It defaults to a multiple of GOMAXPROCS.
	Shards int
	// Full is the policy for a full shard. It defaults to ShrinkWindow.
	Full FullPolicy
}

// Window remembers accepted nonces. It is safe for concurrent use. Its
// zero value is not usable: create one with New.
type Window struct {
	now    func() time.Time
	base   time.Time // the clock at New, with its monotonic reading
	wall   time.Time // base without its monotonic reading
	shards []shard
	seeds  [2]maphash.Seed
	window time.Duration
	skew   time.Duration
	retain int64 // nanoseconds a nonce is remembered
	mask   uint64
	full   FullPolicy
}

type key [2]uint64

type entry struct {
	key    key
	ts     int64 // wall nanoseconds since Window.wall
	forget int64 // monotonic nanoseconds since Window.base
}

type shard struct {
	seen  map[key]struct{}
	ring  []entry // accepted nonces in acceptance order; grows up to limit
	head  int
	n     int
	limit int
	floor int64 // timestamps at or below are stale
	mu    sync.Mutex
	_     [64]byte // keeps neighbouring shards' locks off one cache line
}

// New returns a Window configured by c.
func New(c Config) (*Window, error) {
	if c.Window <= 0 {
		return nil, fmt.Errorf("%w: window %v must be positive", ErrInvalidConfig, c.Window)
	}
	if c.Skew < 0 {
		return nil, fmt.Errorf("%w: skew %v is negative", ErrInvalidConfig, c.Skew)
	}
	if c.Capacity < 0 || c.Shards < 0 {
		return nil, fmt.Errorf("%w: negative capacity or shards", ErrInvalidConfig)
	}
	switch c.Full {
	case ShrinkWindow, RejectNew:
	default:
		return nil, fmt.Errorf("%w: unknown %v", ErrInvalidConfig, c.Full)
	}
	capacity := c.Capacity
	if capacity == 0 {
		capacity = DefaultCapacity
	}
	n := c.Shards
	if n == 0 {
		n = 4 * runtime.GOMAXPROCS(0)
	}
	n = ceilPow2(min(n, capacity))
	for n > 1 && n > capacity {
		n >>= 1
	}
	per := (capacity + n - 1) / n
	now := c.Now
	if now == nil {
		now = time.Now
	}
	base := now()
	w := &Window{
		now:    now,
		base:   base,
		wall:   base.Round(0),
		shards: make([]shard, n),
		seeds:  [2]maphash.Seed{maphash.MakeSeed(), maphash.MakeSeed()},
		window: c.Window,
		skew:   c.Skew,
		retain: satAdd(int64(c.Window), int64(c.Skew)),
		mask:   uint64(n - 1),
		full:   c.Full,
	}
	for i := range w.shards {
		s := &w.shards[i]
		s.seen = make(map[key]struct{})
		s.ring = make([]entry, min(per, initialShardSize))
		s.limit = per
		s.floor = math.MinInt64
	}
	return w, nil
}

// Check accepts the first message with nonce whose timestamp ts lies
// within the window, and returns nil. It returns ErrReplay for a nonce
// already accepted, ErrStale or ErrFuture for a timestamp outside the
// window, ErrFull when a RejectNew window has no room, and ErrEmptyNonce
// for an empty nonce. A rejected message is not remembered.
func (w *Window) Check(ts time.Time, nonce []byte) error {
	if w == nil || w.shards == nil {
		return ErrUninitialized
	}
	if len(nonce) == 0 {
		return ErrEmptyNonce
	}
	return w.check(ts, key{maphash.Bytes(w.seeds[0], nonce), maphash.Bytes(w.seeds[1], nonce)})
}

// CheckString is Check for a nonce held in a string.
func (w *Window) CheckString(ts time.Time, nonce string) error {
	if w == nil || w.shards == nil {
		return ErrUninitialized
	}
	if nonce == "" {
		return ErrEmptyNonce
	}
	return w.check(ts, key{maphash.String(w.seeds[0], nonce), maphash.String(w.seeds[1], nonce)})
}

func (w *Window) check(ts time.Time, k key) error {
	now := w.now()
	// Time.Sub saturates, so extreme timestamps cannot overflow.
	d := ts.Sub(now)
	if d > w.skew {
		return ErrFuture
	}
	if d < -w.window {
		return ErrStale
	}
	mono := int64(now.Sub(w.base))
	tsOff := int64(ts.Round(0).Sub(w.wall))
	s := &w.shards[k[0]&w.mask]
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expire(mono)
	if tsOff <= s.floor {
		return ErrStale
	}
	if _, ok := s.seen[k]; ok {
		return ErrReplay
	}
	if s.n == len(s.ring) && len(s.ring) < s.limit {
		s.grow()
	}
	if s.n == len(s.ring) {
		switch w.full {
		case ShrinkWindow:
			if tsOff <= s.ring[s.head].ts {
				// Forgetting the oldest nonce would raise the
				// floor to this timestamp or above.
				return ErrStale
			}
			s.pop()
		case RejectNew:
			return ErrFull
		}
	}
	i := s.head + s.n
	if i >= len(s.ring) {
		i -= len(s.ring)
	}
	s.ring[i] = entry{key: k, ts: tsOff, forget: satAdd(mono, w.retain)}
	s.n++
	s.seen[k] = struct{}{}
	return nil
}

// grow doubles the ring, up to the shard's limit.
func (s *shard) grow() {
	ring := make([]entry, min(2*len(s.ring), s.limit))
	k := copy(ring, s.ring[s.head:])
	copy(ring[k:], s.ring[:s.head])
	s.ring, s.head = ring, 0
}

// expire forgets the entries whose retention ended before mono.
func (s *shard) expire(mono int64) {
	for s.n > 0 && s.ring[s.head].forget < mono {
		s.pop()
	}
}

// pop forgets the oldest entry and raises the floor to its timestamp.
func (s *shard) pop() {
	e := &s.ring[s.head]
	delete(s.seen, e.key)
	s.floor = max(s.floor, e.ts)
	*e = entry{}
	s.head++
	if s.head == len(s.ring) {
		s.head = 0
	}
	s.n--
}

// Len returns the number of nonces currently remembered, including those
// whose retention ended but that no check has forgotten yet.
func (w *Window) Len() int {
	if w == nil {
		return 0
	}
	total := 0
	for i := range w.shards {
		s := &w.shards[i]
		s.mu.Lock()
		total += s.n
		s.mu.Unlock()
	}
	return total
}

// Capacity returns the number of nonces the Window can remember.
func (w *Window) Capacity() int {
	if w == nil || w.shards == nil {
		return 0
	}
	return len(w.shards) * w.shards[0].limit
}

func satAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	if b < 0 && a < math.MinInt64-b {
		return math.MinInt64
	}
	return a + b
}

func ceilPow2(n int) int {
	if n <= 1 {
		return 1
	}
	return 1 << bits.Len(uint(n-1))
}
