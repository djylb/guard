// Package failban counts failures, such as failed logins, per key and bans
// keys that fail too often.
//
// A Limiter is generic over its key type, so the caller decides what a key
// is: an IP prefix (see AddrPrefix and RemotePrefix), a user name, or a
// struct of both. Callers typically keep one Limiter per kind of key.
//
// # Attempts
//
// Checking IsBanned before an expensive check and calling Fail after it
// is racy: many concurrent requests all see "not banned" and are all
// checked. Attempt reserves the attempt atomically instead: at most
// Threshold attempts per key are in flight or failed within the window,
// and Done settles the reservation:
//
//	ip := ips.Attempt(prefix)
//	user := users.Attempt(name)
//	if !ip.Allowed() || !user.Allowed() {
//		ip.Done(true) // release the reservations without a failure
//		user.Done(true)
//		return errTooManyAttempts
//	}
//	ok := checkPassword(name, password) // slow
//	ip.Done(ok)
//	user.Done(ok)
//
// Done(true) only releases the reservation; it does not clear earlier
// failures. Succeed clears them, which suits a key that the success
// proves is the caller's, such as an account name, but not an IP prefix:
// an attacker could reset its prefix by logging into its own account.
// IsBanned and BannedUntil are read-only and meant for display.
//
// # Counting and bans
//
// Failures are counted in eight buckets per key that together span between
// Window and 8/7 of Window, so counting errs towards banning. When a key
// reaches Threshold failures it is banned for BanDuration. If
// MaxBanDuration is longer, each further ban within Cooldown after the
// previous one ended lasts twice as long, up to MaxBanDuration.
//
// # Memory
//
// A Limiter holds at most Capacity pending failure counters and MaxBans
// ban records, split evenly across its shards. Memory is reclaimed
// deterministically by the calls that change a shard and by Sweep; there
// are no background goroutines and no randomly triggered sweeps. Every
// operation takes amortised constant time, apart from Bans, Stats, Sweep
// and Reset, which visit every shard.
//
// When a shard has Capacity counters, a new key evicts the counter updated
// least recently. An attacker flooding the limiter with new keys can thus
// reset the pending counters, and reservations, of other keys, but never
// lift a ban.
//
// When a shard holds MaxBans records and a key reaches Threshold, records
// of ended bans kept only for Cooldown are dropped first. If every record
// is an active ban, Config.Full decides; Stats counts both outcomes:
//
//   - LockShard, the default, keeps every ban and locks the shard down
//     until its earliest ban ends: every key in the shard is reported
//     banned, and keys that reach Threshold meanwhile wait for a record,
//     reported banned. No ban ever ends early, but whoever fills the table
//     locks every legitimate user of the shard out. It is the default
//     because keys that cost an attacker nothing, such as user names,
//     would otherwise let it lift the ban on a targeted account by
//     banning made-up names.
//   - EvictSoonest ends the ban that would end soonest to make room, and
//     keeps the evicted key one failure away from its next, longer ban,
//     as long as it has a counter. It suits limiters keyed by IP prefix:
//     an attacker that can fill the table controls many prefixes, so the
//     bans that end early are mostly its own oldest ones, while
//     legitimate users are unaffected.
//
// Size MaxBans so that it is only reached under a distributed attack.
// Note that a single IPv6 /48 holds 65536 /64 prefixes: put a limiter
// keyed by a wider prefix, such as /48, in front of a /64 one so that one
// network cannot fill the ban table.
//
// # Clocks
//
// All durations are measured on the monotonic clock with nanosecond
// precision, so stepping the wall clock neither lifts nor extends bans.
package failban

import (
	"errors"
	"fmt"
	"hash/maphash"
	"math"
	"math/bits"
	"runtime"
	"slices"
	"sync"
	"time"
)

// Defaults used for zero Config fields.
const (
	DefaultThreshold   = 5
	DefaultWindow      = 15 * time.Minute
	DefaultBanDuration = 15 * time.Minute
	DefaultCapacity    = 1 << 16
	DefaultMaxBans     = 1 << 16
)

// ErrInvalidConfig reports a Config that New cannot use.
var ErrInvalidConfig = errors.New("failban: invalid config")

// FullPolicy decides what a Limiter does when a key reaches Threshold and
// its shard's ban table holds MaxBans active bans. See the package
// documentation for the trade-off.
type FullPolicy int

const (
	// LockShard keeps every ban and reports every key of the shard
	// banned until its earliest ban ends.
	LockShard FullPolicy = iota
	// EvictSoonest ends the ban that would end soonest to make room.
	EvictSoonest
)

// String returns the policy's name.
func (p FullPolicy) String() string {
	switch p {
	case LockShard:
		return "LockShard"
	case EvictSoonest:
		return "EvictSoonest"
	default:
		return fmt.Sprintf("FullPolicy(%d)", int(p))
	}
}

const buckets = 8 // per counter; a power of two

// Config configures a Limiter. Its zero value selects the defaults.
type Config struct {
	// Now returns the current time. It defaults to time.Now.
	Now func() time.Time
	// Threshold is the number of failures within Window that bans a
	// key, and the number of attempts that may be in flight or failed
	// at once. It defaults to DefaultThreshold.
	Threshold int
	// Window is the period over which failures are counted. It
	// defaults to DefaultWindow.
	Window time.Duration
	// BanDuration is the length of a first ban. It defaults to
	// DefaultBanDuration.
	BanDuration time.Duration
	// MaxBanDuration caps bans that double for repeat offenders. It
	// defaults to BanDuration, which disables the growth.
	MaxBanDuration time.Duration
	// Cooldown is how long after a ban ends the key's offences are
	// remembered, so that the next ban is longer. It defaults to
	// MaxBanDuration when bans grow and to zero otherwise.
	Cooldown time.Duration
	// Capacity is the maximum number of keys with pending failures. It
	// defaults to DefaultCapacity. Memory grows with use, by roughly 150
	// bytes plus the key per counter.
	Capacity int
	// MaxBans is the maximum number of ban records, active or in
	// cooldown. It defaults to DefaultMaxBans.
	MaxBans int
	// Shards is the number of independently locked shards, rounded up
	// to a power of two and lowered so that each shard holds at least
	// one counter and one ban. It defaults to a multiple of GOMAXPROCS.
	Shards int
	// Full is the policy for a full ban table. It defaults to
	// LockShard.
	Full FullPolicy
}

// Ban describes an active ban.
type Ban[K comparable] struct {
	// Key is the banned key.
	Key K
	// Until is when the ban ends.
	Until time.Time
	// Offences is the number of bans of this key in a row, counting
	// this one.
	Offences int
}

// Stats is a snapshot of a Limiter's size.
type Stats struct {
	// Pending is the number of keys with failures or attempts in flight
	// but no ban.
	Pending int
	// Banned is the number of active bans.
	Banned int
	// Cooling is the number of ended bans remembered for Cooldown.
	Cooling int
	// Waiting is the number of keys that reached Threshold in a locked
	// shard and wait for a ban record; they are reported banned.
	Waiting int
	// LockedShards is the number of shards in lockdown because their
	// ban table is full (LockShard).
	LockedShards int
	// Evicted is the number of active bans ended early to make room
	// since New (EvictSoonest).
	Evicted uint64
}

// Limiter counts failures per key and bans keys. It is safe for
// concurrent use. Create one with New; the zero value reports every key
// banned and records nothing.
//
// K must be a type whose values can be map keys without panicking; an
// interface type holding an uncomparable value panics, as in a map.
type Limiter[K comparable] struct {
	now       func() time.Time
	base      time.Time // the clock at New, with its monotonic reading
	wall      time.Time // base without its monotonic reading
	shards    []shard[K]
	seed      maphash.Seed
	width     int64 // nanoseconds per bucket
	ban       int64
	maxBan    int64
	cooldown  int64
	mask      uint64
	threshold uint64
	full      FullPolicy
}

type counter[K comparable] struct {
	key        K
	prev, next *counter[K] // recency list, without waiting counters; the shard's root is the sentinel
	newest     int64       // bucket index of the newest bucket
	inflight   uint64      // attempts reserved and not yet done
	offences   int         // of a ban EvictSoonest ended early
	counts     [buckets]uint32
	waiting    bool // reached Threshold, waits in shard.waiting for a record
}

type record[K comparable] struct {
	key      K
	until    int64
	offences int
	index    int // in shard.heap
}

type shard[K comparable] struct {
	counters    map[K]*counter[K]
	bans        map[K]*record[K]
	heap        []*record[K]  // min-heap of bans by until
	waiting     []*counter[K] // FIFO of counters waiting for a record; may hold stale entries
	root        counter[K]    // root.next is the most recent counter
	maxCounters int
	maxBans     int
	lockedUntil int64 // the shard is in lockdown before this time
	evicted     uint64
	mu          sync.RWMutex
	_           [64]byte // keeps neighbouring shards' locks off one cache line
}

// New returns a Limiter configured by c.
func New[K comparable](c Config) (*Limiter[K], error) {
	if c.Threshold < 0 || c.Window < 0 || c.BanDuration < 0 || c.MaxBanDuration < 0 ||
		c.Cooldown < 0 || c.Capacity < 0 || c.MaxBans < 0 || c.Shards < 0 {
		return nil, fmt.Errorf("%w: negative field in %+v", ErrInvalidConfig, c)
	}
	switch c.Full {
	case LockShard, EvictSoonest:
	default:
		return nil, fmt.Errorf("%w: unknown %v", ErrInvalidConfig, c.Full)
	}
	threshold := orDefault(c.Threshold, DefaultThreshold)
	window := orDefault(c.Window, DefaultWindow)
	ban := orDefault(c.BanDuration, DefaultBanDuration)
	maxBan := orDefault(c.MaxBanDuration, ban)
	if maxBan < ban {
		return nil, fmt.Errorf("%w: MaxBanDuration %v shorter than BanDuration %v", ErrInvalidConfig, maxBan, ban)
	}
	cooldown := c.Cooldown
	if cooldown == 0 && maxBan > ban {
		cooldown = maxBan
	}
	capacity := orDefault(c.Capacity, DefaultCapacity)
	maxBans := orDefault(c.MaxBans, DefaultMaxBans)
	n := c.Shards
	if n == 0 {
		n = 4 * runtime.GOMAXPROCS(0)
	}
	limit := min(capacity, maxBans)
	n = ceilPow2(min(n, limit))
	for n > 1 && n > limit {
		n >>= 1
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	base := now()
	l := &Limiter[K]{
		now:       now,
		base:      base,
		wall:      base.Round(0),
		shards:    make([]shard[K], n),
		seed:      maphash.MakeSeed(),
		width:     bucketWidth(window),
		ban:       int64(ban),
		maxBan:    int64(maxBan),
		cooldown:  int64(cooldown),
		mask:      uint64(n - 1),
		threshold: uint64(threshold),
		full:      c.Full,
	}
	for i := range l.shards {
		s := &l.shards[i]
		s.counters = make(map[K]*counter[K])
		s.bans = make(map[K]*record[K])
		s.root.prev, s.root.next = &s.root, &s.root
		s.maxCounters = (capacity + n - 1) / n
		s.maxBans = (maxBans + n - 1) / n
	}
	return l, nil
}

// MustNew is New for configurations known to be valid; it panics if New
// returns an error.
func MustNew[K comparable](c Config) *Limiter[K] {
	l, err := New[K](c)
	if err != nil {
		panic(err)
	}
	return l
}

func orDefault[T int | time.Duration](v, def T) T {
	if v == 0 {
		return def
	}
	return v
}

func (l *Limiter[K]) ready() bool {
	return l != nil && l.shards != nil
}

// clock returns the current time in nanoseconds since New and the shard
// of key. It runs before any lock is taken, so a Now that blocks or calls
// back into the Limiter cannot deadlock it.
func (l *Limiter[K]) clock(key K) (int64, *shard[K]) {
	t := l.mono()
	return t, &l.shards[maphash.Comparable(l.seed, key)&l.mask]
}

func (l *Limiter[K]) mono() int64 {
	return int64(l.now().Sub(l.base))
}

func (l *Limiter[K]) at(t int64) time.Time {
	return l.wall.Add(time.Duration(t))
}

func (l *Limiter[K]) bucket(t int64) int64 {
	q := t / l.width
	if t%l.width != 0 && t < 0 {
		q--
	}
	return q
}

// Attempt is a reservation of one attempt for a key, made by
// Limiter.Attempt. Call Done exactly once, also for an attempt that was
// not allowed; a reservation that is never done keeps counting against
// its key until its counter is evicted.
type Attempt[K comparable] struct {
	l       *Limiter[K]
	c       *counter[K]
	key     K
	until   time.Time
	allowed bool
	done    bool
}

// Attempt reserves an attempt for key, such as a password check. The
// attempt is allowed if key is not banned and its failures within the
// window plus its attempts in flight are fewer than Threshold; then it
// counts as in flight until Done.
func (l *Limiter[K]) Attempt(key K) Attempt[K] {
	a := Attempt[K]{l: l, key: key}
	if !l.ready() {
		return a
	}
	t, s := l.clock(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(l, t)
	if r := s.bans[key]; r != nil && r.until > t {
		a.until = l.at(r.until)
		return a
	}
	if t < s.lockedUntil {
		a.until = l.at(s.lockedUntil)
		return a
	}
	i := l.bucket(t)
	c := s.counters[key]
	if c != nil && c.waiting {
		a.until = l.at(satAdd(t, l.ban))
		return a
	}
	if c != nil && c.count(i)+c.inflight >= l.threshold {
		return a // Threshold attempts are in flight: retry later
	}
	if c = s.counter(key, i); c == nil {
		a.until = l.at(s.lockdown())
		return a
	}
	c.inflight++
	a.c = c
	a.allowed = true
	return a
}

// Allowed reports whether the attempt may proceed.
func (a *Attempt[K]) Allowed() bool {
	return a.allowed
}

// Until returns when the ban that refused the attempt ends. It is the
// zero Time for an allowed attempt, and for one refused because Threshold
// attempts of the key were in flight.
func (a *Attempt[K]) Until() time.Time {
	return a.until
}

// Done settles the attempt: ok releases the reservation without touching
// the key's failures, and !ok records it as a failure, as Fail does. It
// reports whether the key is banned afterwards, and until when. Calls
// after the first, and calls on an attempt that was not allowed, do
// nothing.
func (a *Attempt[K]) Done(ok bool) (until time.Time, banned bool) {
	if !a.allowed || a.done {
		return time.Time{}, false
	}
	a.done = true
	l := a.l
	t, s := l.clock(a.key)
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.counters[a.key] == a.c
	if current && a.c.inflight > 0 {
		a.c.inflight--
	}
	s.sweep(l, t)
	if ok {
		return time.Time{}, false
	}
	r := s.bans[a.key]
	if r != nil && r.until > t {
		return l.at(r.until), true
	}
	// The counter may be gone, evicted or reset meanwhile: then the
	// failure is counted in a new one.
	if u, b := s.fail(l, a.key, r, t); b {
		return l.at(u), true
	}
	return time.Time{}, false
}

// Fail records a failure of key. It reports whether key is banned after
// it, and until when. A failure of a key that is already banned is not
// counted and does not extend the ban. Fail suits failures found without
// a reservation; around an expensive check use Attempt.
func (l *Limiter[K]) Fail(key K) (until time.Time, banned bool) {
	if !l.ready() {
		return time.Time{}, true
	}
	t, s := l.clock(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(l, t)
	r := s.bans[key]
	if r != nil && r.until > t {
		return l.at(r.until), true
	}
	u, b := s.fail(l, key, r, t)
	if !b {
		return time.Time{}, false
	}
	return l.at(u), true
}

// fail counts a failure of key, which has no active ban but maybe the
// record r of an ended one, and bans it at Threshold.
func (s *shard[K]) fail(l *Limiter[K], key K, r *record[K], t int64) (int64, bool) {
	i := l.bucket(t)
	c := s.counter(key, i)
	if c == nil {
		return s.lockdown(), true
	}
	c.add(i)
	if c.waiting || c.count(i) >= l.threshold {
		if r == nil && !s.room(l, t) {
			// LockShard with every record an active ban: keep the
			// counter waiting for a record, and lock the shard
			// down until its earliest ban ends.
			if !c.waiting {
				c.unlink()
				c.waiting = true
				s.waiting = append(s.waiting, c)
			}
			return s.lockdown(), true
		}
		until := s.ban(l, key, r, c.offences, t)
		s.removeCounter(c)
		return until, true
	}
	if t < s.lockedUntil {
		return s.lockedUntil, true
	}
	return 0, false
}

// counter returns key's counter, created if needed and moved to the front
// of the recency list, or nil if every counter of the full shard waits for
// a ban record.
func (s *shard[K]) counter(key K, i int64) *counter[K] {
	if c := s.counters[key]; c != nil {
		if !c.waiting {
			c.unlink()
			c.linkAfter(&s.root)
		}
		return c
	}
	if len(s.counters) >= s.maxCounters {
		victim := s.root.prev
		if victim == &s.root {
			return nil
		}
		s.removeCounter(victim)
	}
	c := &counter[K]{key: key, newest: i}
	s.counters[key] = c
	c.linkAfter(&s.root)
	return c
}

// lockdown locks the full shard down until its earliest ban ends and
// returns that time.
func (s *shard[K]) lockdown() int64 {
	if len(s.heap) > 0 {
		s.lockedUntil = max(s.lockedUntil, s.heap[0].until)
	}
	return s.lockedUntil
}

// room makes room for a new ban record if the policy allows it, and
// reports whether there is room.
func (s *shard[K]) room(l *Limiter[K], t int64) bool {
	if len(s.bans) < s.maxBans {
		return true
	}
	oldest := s.heap[0]
	if oldest.until > t {
		switch l.full {
		case LockShard:
			return false
		case EvictSoonest:
			s.evicted++
			s.keepOffences(l, oldest, t)
		}
	}
	s.removeRecord(oldest)
	return true
}

// keepOffences leaves the key of an evicted ban one failure away from its
// next ban, if there is room for a counter.
func (s *shard[K]) keepOffences(l *Limiter[K], r *record[K], t int64) {
	if _, ok := s.counters[r.key]; ok || len(s.counters) >= s.maxCounters {
		return
	}
	i := l.bucket(t)
	c := &counter[K]{key: r.key, newest: i, offences: r.offences}
	c.counts[uint64(i)%buckets] = uint32(min(l.threshold-1, math.MaxUint32))
	s.counters[r.key] = c
	c.linkAfter(&s.root)
}

// ban bans key from t, with its record r of earlier offences if any, or
// else prior offences, and returns the end of the ban. The caller made
// room for a new record.
func (s *shard[K]) ban(l *Limiter[K], key K, r *record[K], prior int, t int64) int64 {
	if r == nil {
		r = &record[K]{key: key, offences: prior}
		s.bans[key] = r
		r.index = len(s.heap)
		s.heap = append(s.heap, r)
	}
	if r.offences < math.MaxInt {
		r.offences++
	}
	r.until = satAdd(t, l.duration(r.offences))
	s.fix(r.index)
	return r.until
}

// duration returns the length of the offences-th ban in a row.
func (l *Limiter[K]) duration(offences int) int64 {
	d := l.ban
	for i := 1; i < offences && d < l.maxBan; i++ {
		if d > l.maxBan/2 {
			return l.maxBan
		}
		d *= 2
	}
	return min(d, l.maxBan)
}

// Succeed clears key's pending failures, as after a successful login. It
// does not lift a ban, forget past offences or release reservations. Use
// it only for keys that the success proves are the caller's, such as an
// account name: on an IP limiter, an attacker could clear its failures by
// logging into its own account.
func (l *Limiter[K]) Succeed(key K) {
	if !l.ready() {
		return
	}
	t, s := l.clock(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(l, t)
	if c := s.counters[key]; c != nil && !c.waiting {
		if c.inflight > 0 {
			c.counts = [buckets]uint32{}
		} else {
			s.removeCounter(c)
		}
	}
}

// IsBanned reports whether key is banned. It never changes the Limiter.
// Use it for display; to guard an attempt, use Attempt.
func (l *Limiter[K]) IsBanned(key K) bool {
	_, banned := l.BannedUntil(key)
	return banned
}

// BannedUntil reports whether key is banned and until when. It never
// changes the Limiter. A key waiting for a ban record in a locked shard is
// reported banned until one BanDuration from now.
func (l *Limiter[K]) BannedUntil(key K) (until time.Time, banned bool) {
	if !l.ready() {
		return time.Time{}, true
	}
	t, s := l.clock(key)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r := s.bans[key]; r != nil && r.until > t {
		return l.at(r.until), true
	}
	if t < s.lockedUntil {
		return l.at(s.lockedUntil), true
	}
	if c := s.counters[key]; c != nil && c.waiting {
		// Its ban starts when a record frees up.
		return l.at(satAdd(t, l.ban)), true
	}
	return time.Time{}, false
}

// Failures returns the number of key's failures counted in the current
// window, without attempts in flight. It is zero while key is banned. It
// never changes the Limiter.
func (l *Limiter[K]) Failures(key K) int {
	if !l.ready() {
		return 0
	}
	t, s := l.clock(key)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c := s.counters[key]; c != nil {
		return int(min(c.count(l.bucket(t)), math.MaxInt32))
	}
	return 0
}

// Unban lifts key's ban, forgets its offences, failures and reservations.
// It reports whether key had a ban record or a counter.
func (l *Limiter[K]) Unban(key K) bool {
	if !l.ready() {
		return false
	}
	t, s := l.clock(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	if r := s.bans[key]; r != nil {
		s.removeRecord(r)
		s.lockedUntil = 0
		found = true
	}
	if c := s.counters[key]; c != nil {
		s.removeCounter(c)
		found = true
	}
	s.sweep(l, t)
	return found
}

// Reset lifts every ban and forgets every failure and reservation.
func (l *Limiter[K]) Reset() {
	if !l.ready() {
		return
	}
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		clear(s.counters)
		clear(s.bans)
		clear(s.heap)
		s.heap = s.heap[:0]
		clear(s.waiting)
		s.waiting = s.waiting[:0]
		s.root.prev, s.root.next = &s.root, &s.root
		s.lockedUntil = 0
		s.mu.Unlock()
	}
}

// Sweep frees the memory of expired counters and of bans whose cooldown
// ended. Calls that change a shard sweep it already; Sweep reclaims memory
// in shards that are no longer used, for example from a periodic task the
// caller owns.
func (l *Limiter[K]) Sweep() {
	if !l.ready() {
		return
	}
	t := l.mono()
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		s.sweep(l, t)
		s.mu.Unlock()
	}
}

// Bans returns the active bans, ordered by the time they end.
func (l *Limiter[K]) Bans() []Ban[K] {
	if !l.ready() {
		return nil
	}
	t := l.mono()
	var list []Ban[K]
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.RLock()
		for _, r := range s.heap {
			if r.until > t {
				list = append(list, Ban[K]{Key: r.key, Until: l.at(r.until), Offences: r.offences})
			}
		}
		s.mu.RUnlock()
	}
	slices.SortFunc(list, func(a, b Ban[K]) int { return a.Until.Compare(b.Until) })
	return list
}

// Stats returns a snapshot of the Limiter's size.
func (l *Limiter[K]) Stats() Stats {
	var st Stats
	if !l.ready() {
		return st
	}
	t := l.mono()
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.RLock()
		st.Pending += len(s.counters)
		for _, r := range s.heap {
			if r.until > t {
				st.Banned++
			} else {
				st.Cooling++
			}
		}
		if t < s.lockedUntil {
			st.LockedShards++
		}
		for _, c := range s.waiting {
			if c.waiting {
				st.Waiting++
			}
		}
		st.Evicted += s.evicted
		s.mu.RUnlock()
	}
	return st
}

// sweep drops counters that count nothing and have no attempt in flight,
// starting with the least recently updated, and ban records whose
// cooldown ended, then bans the keys waiting for a record while there is
// room. A counter with an attempt in flight stops the first loop until it
// is updated again.
func (s *shard[K]) sweep(l *Limiter[K], t int64) {
	i := l.bucket(t)
	for c := s.root.prev; c != &s.root && c.inflight == 0 && c.count(i) == 0; c = s.root.prev {
		s.removeCounter(c)
	}
	for len(s.heap) > 0 && satAdd(s.heap[0].until, l.cooldown) <= t {
		s.removeRecord(s.heap[0])
	}
	for len(s.waiting) > 0 {
		c := s.waiting[0]
		if c.waiting {
			if !s.room(l, t) {
				break
			}
			s.ban(l, c.key, nil, c.offences, t)
			s.removeCounter(c)
		}
		s.waiting[0] = nil
		s.waiting = s.waiting[1:]
	}
	if len(s.waiting) == 0 {
		s.waiting = s.waiting[:0:0] // release the shifted-away array
	}
}

// removeCounter forgets c; a stale entry of c in s.waiting is skipped.
func (s *shard[K]) removeCounter(c *counter[K]) {
	if c.prev != nil {
		c.unlink()
	}
	c.waiting = false
	delete(s.counters, c.key)
}

func (c *counter[K]) unlink() {
	c.prev.next = c.next
	c.next.prev = c.prev
	c.prev, c.next = nil, nil
}

func (c *counter[K]) linkAfter(at *counter[K]) {
	c.prev = at
	c.next = at.next
	at.next.prev = c
	at.next = c
}

// add counts a failure in bucket i.
func (c *counter[K]) add(i int64) {
	if i > c.newest {
		if i-c.newest >= buckets {
			c.counts = [buckets]uint32{}
		} else {
			for j := c.newest + 1; j <= i; j++ {
				c.counts[uint64(j)%buckets] = 0
			}
		}
		c.newest = i
	}
	// A clock that went back counts in the newest bucket.
	if b := &c.counts[uint64(c.newest)%buckets]; *b < math.MaxUint32 {
		*b++
	}
}

// count returns the failures in the buckets that bucket i's window covers.
func (c *counter[K]) count(i int64) uint64 {
	var n uint64
	for j := max(c.newest-buckets+1, i-buckets+1); j <= c.newest; j++ {
		n += uint64(c.counts[uint64(j)%buckets])
	}
	return n
}

func (s *shard[K]) removeRecord(r *record[K]) {
	delete(s.bans, r.key)
	last := len(s.heap) - 1
	i := r.index
	if i != last {
		s.swap(i, last)
	}
	s.heap[last] = nil
	s.heap = s.heap[:last]
	if i != last {
		s.fix(i)
	}
}

// fix restores the heap order after the record at i changed.
func (s *shard[K]) fix(i int) {
	if !s.down(i) {
		s.up(i)
	}
}

func (s *shard[K]) up(i int) {
	for i > 0 {
		p := (i - 1) / 2
		if s.heap[p].until <= s.heap[i].until {
			return
		}
		s.swap(i, p)
		i = p
	}
}

func (s *shard[K]) down(i int) bool {
	start := i
	for {
		m := i
		for _, c := range [2]int{2*i + 1, 2*i + 2} {
			if c < len(s.heap) && s.heap[c].until < s.heap[m].until {
				m = c
			}
		}
		if m == i {
			return i > start
		}
		s.swap(i, m)
		i = m
	}
}

func (s *shard[K]) swap(i, j int) {
	s.heap[i], s.heap[j] = s.heap[j], s.heap[i]
	s.heap[i].index = i
	s.heap[j].index = j
}

// bucketWidth returns the bucket width, rounded up, that makes buckets-1
// buckets cover window.
func bucketWidth(window time.Duration) int64 {
	w := int64(window) / (buckets - 1)
	if int64(window)%(buckets-1) != 0 {
		w++
	}
	return max(1, w)
}

func satAdd(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

func ceilPow2(n int) int {
	if n <= 1 {
		return 1
	}
	return 1 << bits.Len(uint(n-1))
}
