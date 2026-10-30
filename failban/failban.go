// Package failban counts failures, such as failed logins, per key and bans
// keys that fail too often.
//
// A Limiter is generic over its key type, so the caller decides what a key
// is: an IP prefix (see PrefixLen), a user name, or a struct of both.
// Callers typically keep one Limiter per kind of key.
//
// # Attempts
//
// Checking IsBanned before an expensive check and calling Fail after it
// is racy: many concurrent requests all see "not banned" and are all
// checked. Attempt reserves the attempt atomically instead: at most
// Threshold attempts per key are in flight or failed within the window,
// and Fail, Release or Succeed settles the reservation:
//
//	ip := ips.Attempt(prefix)
//	if !ip.Allowed() {
//		return tooManyAttempts(ip.RetryAfter())
//	}
//	user := users.Attempt(name)
//	if !user.Allowed() {
//		ip.Release()
//		return tooManyAttempts(user.RetryAfter())
//	}
//	if !checkPassword(name, password) { // slow
//		ip.Fail()
//		user.Fail()
//		return errWrongPassword
//	}
//	ip.Release()
//	user.Succeed()
//
// Reserve the cheaper, wider key first and stop when it is refused, so
// that a banned client does not touch the other limiter at all.
//
// Release settles the reservation without a failure; it does not clear
// earlier failures. Succeed also clears them, which suits a key that the
// success proves is the caller's, such as an account name, but not an IP
// prefix: an attacker could reset its prefix by logging into its own
// account. IsBanned and BannedUntil are read-only and meant for display.
//
// Limiter.Fail and Limiter.Succeed act without a reservation. Use Fail
// for failures found without an expensive check to guard, such as a
// malformed or forged request, and Succeed to clear an account's failures
// after it proved itself another way, such as by a password reset. Around
// an expensive check, always use Attempt.
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
// A Limiter holds at most MaxPending pending failure counters and MaxBans
// ban records, split evenly across its shards. Memory is reclaimed
// deterministically by the calls that change a shard and by Sweep; there
// are no background goroutines and no randomly triggered sweeps. Every
// operation takes amortised constant time, apart from Bans, Stats, Sweep
// and Reset, which visit every shard.
//
// A counter lives only while its key has failures in the window,
// attempts in flight or the offences of an evicted ban: settling an
// attempt that leaves nothing to count frees the counter at once. When a
// shard has MaxPending counters, a new key evicts the counter updated
// least recently. An attacker flooding the limiter with new keys can thus
// reset the pending counters, and reservations, of other keys, but only
// with failures or attempts held in flight, never with attempts it
// settles at once, and it never lifts a ban.
//
// Limits apply per shard: each holds MaxPending/Shards counters and
// MaxBans/Shards records. The default shard count keeps each shard at 256
// entries or more, so a small limiter has a single shard.
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
// # Persistence
//
// A Limiter lives in memory. A service that wants bans to survive a
// restart saves Bans when it stops and passes each to Ban when it starts
// again. Bans includes the records of ended bans still in their
// cooldown, so repeat offenders keep their longer bans; pending failures
// are not kept.
//
// # Clocks
//
// All durations are measured on the monotonic clock with nanosecond
// precision, so stepping the wall clock neither lifts nor extends bans.
package failban

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"math"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/djylb/guard/internal/clock"
	"github.com/djylb/guard/internal/conf"
	"github.com/djylb/guard/internal/num"
)

// Defaults of zero Config fields.
const (
	DefaultThreshold   = 5
	DefaultWindow      = 15 * time.Minute
	DefaultBanDuration = 15 * time.Minute
	DefaultMaxPending  = 1 << 16
	DefaultMaxBans     = 1 << 16
)

var (
	// ErrInvalidConfig reports a Config that New cannot use.
	ErrInvalidConfig = errors.New("failban: invalid config")
	// ErrFull reports that Ban found no room in a LockShard ban table
	// whose records are all active bans.
	ErrFull = errors.New("failban: ban table full")
	// ErrUninitialized reports a Limiter not created by New.
	ErrUninitialized = errors.New("failban: limiter not created by New")
)

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

var policyNames = [...]string{LockShard: "LockShard", EvictSoonest: "EvictSoonest"}

// String returns the policy's name.
//
//goland:noinspection GoMixedReceiverTypes
func (p FullPolicy) String() string {
	if p >= 0 && int(p) < len(policyNames) {
		return policyNames[p]
	}
	return fmt.Sprintf("FullPolicy(%d)", int(p))
}

// ParseFullPolicy returns the policy whose String form is s, ignoring
// case.
func ParseFullPolicy(s string) (FullPolicy, error) {
	i, ok := conf.ParseName(s, policyNames[:]...)
	if !ok {
		return 0, fmt.Errorf("%w: unknown full policy %q", ErrInvalidConfig, s)
	}
	return FullPolicy(i), nil
}

// MarshalText implements encoding.TextMarshaler with the String form; an
// unknown policy is an error.
//
//goland:noinspection GoMixedReceiverTypes
func (p FullPolicy) MarshalText() ([]byte, error) {
	if p < 0 || int(p) >= len(policyNames) {
		return nil, fmt.Errorf("%w: unknown %v", ErrInvalidConfig, p)
	}
	return []byte(policyNames[p]), nil
}

// UnmarshalText implements encoding.TextUnmarshaler with ParseFullPolicy.
//
//goland:noinspection GoMixedReceiverTypes
func (p *FullPolicy) UnmarshalText(text []byte) error {
	v, err := ParseFullPolicy(string(text))
	if err == nil {
		*p = v
	}
	return err
}

const buckets = 8 // per counter; a power of two

// maxSpare is the number of removed counters a shard keeps for reuse, so
// that attempts on keys without failures do not allocate.
const maxSpare = 8

// Config configures a Limiter. Its zero value selects the defaults.
type Config struct {
	// Now returns the current time. It defaults to time.Now.
	Now func() time.Time
	// Threshold is the number of failures within Window that bans a
	// key, and the number of attempts that may be in flight or failed
	// at once. It defaults to DefaultThreshold and must fit in a uint32,
	// the size of the failure counts.
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
	// MaxPending is the maximum number of keys with pending failures or
	// attempts in flight. It defaults to DefaultMaxPending. Memory grows
	// with use, by roughly 150 bytes plus the key per counter.
	MaxPending int
	// MaxBans is the maximum number of ban records, active or in
	// cooldown. It defaults to DefaultMaxBans.
	MaxBans int
	// Shards is the number of independently locked shards, rounded up
	// to a power of two and lowered so that each shard holds at least
	// one counter and one ban. It defaults to a multiple of GOMAXPROCS,
	// lowered so that each shard holds at least 256 counters and bans.
	// MaxPending, MaxBans and Full apply per shard.
	Shards int
	// Full is the policy for a full ban table. It defaults to
	// LockShard.
	Full FullPolicy
}

// jsonConfig is the JSON form of a Config.
type jsonConfig struct {
	Threshold      int           `json:"threshold"`
	Window         conf.Duration `json:"window"`
	BanDuration    conf.Duration `json:"ban_duration"`
	MaxBanDuration conf.Duration `json:"max_ban_duration"`
	Cooldown       conf.Duration `json:"cooldown"`
	MaxPending     int           `json:"max_pending"`
	MaxBans        int           `json:"max_bans"`
	Shards         int           `json:"shards"`
	Full           FullPolicy    `json:"full"`
}

//goland:noinspection GoMixedReceiverTypes
func (c *Config) json() jsonConfig {
	return jsonConfig{
		Threshold:      c.Threshold,
		Window:         conf.Duration(c.Window),
		BanDuration:    conf.Duration(c.BanDuration),
		MaxBanDuration: conf.Duration(c.MaxBanDuration),
		Cooldown:       conf.Duration(c.Cooldown),
		MaxPending:     c.MaxPending,
		MaxBans:        c.MaxBans,
		Shards:         c.Shards,
		Full:           c.Full,
	}
}

// UnmarshalJSON reads a Config from a JSON object such as
//
//	{"threshold": 5, "window": "15m", "ban_duration": "1m", "max_ban_duration": "24h"}
//
// with the fields threshold, window, ban_duration, max_ban_duration,
// cooldown, max_pending, max_bans, shards and full. Durations are strings
// in the form of time.ParseDuration; the policy is a name as its String
// method returns it. Fields that are absent keep their value; unknown,
// repeated and null fields are an error, and names must match exactly.
// Now cannot be set from JSON.
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) UnmarshalJSON(data []byte) error {
	v := c.json()
	if err := conf.Decode(data, &v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	*c = Config{
		Now:            c.Now,
		Threshold:      v.Threshold,
		Window:         time.Duration(v.Window),
		BanDuration:    time.Duration(v.BanDuration),
		MaxBanDuration: time.Duration(v.MaxBanDuration),
		Cooldown:       time.Duration(v.Cooldown),
		MaxPending:     v.MaxPending,
		MaxBans:        v.MaxBans,
		Shards:         v.Shards,
		Full:           v.Full,
	}
	return nil
}

// MarshalJSON writes c in the form UnmarshalJSON reads, without Now.
//
//goland:noinspection GoMixedReceiverTypes
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.json())
}

// Ban is a ban record, as Bans lists them and Ban takes them: an active
// ban, or one that ended and whose offences are remembered for Cooldown.
type Ban[K comparable] struct {
	// Key is the banned key.
	Key K
	// Until is when the ban ends, or ended.
	Until time.Time
	// Offences is the number of bans of this key in a row, counting
	// this one.
	Offences int
}

// Result is the state of a key after a failure.
type Result struct {
	// Until is when the key's ban ends; zero if it is not banned.
	Until time.Time
	// Offences is the number of bans of the key in a row, counting the
	// current one; zero while the key is banned only by a lockdown or
	// waits for a ban record.
	Offences int
	// Banned reports whether the key is banned.
	Banned bool
	// Started reports whether this failure started the ban, for
	// logging each ban once.
	Started bool
}

// Stats is a snapshot of a Limiter's size and counters. The counters run
// from New, and Reset does not clear them.
type Stats struct {
	// Pending is the number of keys with failures or attempts in flight
	// but no ban, without the Waiting ones.
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
	// Failures is the number of failures counted.
	Failures uint64
	// Started is the number of bans started, by failures or by Ban.
	Started uint64
	// Refused is the number of attempts refused, because the key was
	// banned or its attempts were all in flight.
	Refused uint64
	// Evicted is the number of active bans ended early to make room
	// (EvictSoonest).
	Evicted uint64
}

// Limiter counts failures per key and bans keys. It is safe for
// concurrent use. Create one with New; the zero value reports every key
// banned and records nothing.
//
// K must be a type whose values can be map keys without panicking; an
// interface type holding an uncomparable value panics, as in a map.
type Limiter[K comparable] struct {
	clock     clock.Clock
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
	slots      []slot      // reservations; in use or on the free list
	newest     int64       // bucket index of the newest bucket
	inflight   uint64      // slots in use
	offences   int         // of a ban EvictSoonest ended early
	free       int         // 1 + index of the first free slot; 0 if none
	counts     [buckets]uint32
	waiting    bool // reached Threshold, waits in shard.waiting for a record
	queued     bool // was put on shard.waiting, which may still point to it
}

// slot identifies one reservation, so that an Attempt settles it at most
// once even if the Attempt was copied: settling bumps the generation,
// which only grows, also when the counter is reused.
type slot struct {
	gen  uint64
	next int // free list link, as counter.free
	used bool
}

// reserve takes a slot and returns its index and generation.
func (c *counter[K]) reserve() (int, uint64) {
	var i int
	if c.free != 0 {
		i = c.free - 1
		c.free = c.slots[i].next
	} else {
		i = len(c.slots)
		c.slots = append(c.slots, slot{})
	}
	c.slots[i].used = true
	c.inflight++
	return i, c.slots[i].gen
}

// release frees slot i if it is still the reservation of generation gen,
// and reports whether it was.
func (c *counter[K]) release(i int, gen uint64) bool {
	if i < 0 || i >= len(c.slots) {
		return false
	}
	sl := &c.slots[i]
	if !sl.used || sl.gen != gen {
		return false
	}
	sl.used, sl.next = false, c.free
	sl.gen++
	c.free = i + 1
	c.inflight--
	return true
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
	spare       []*counter[K] // removed counters kept for reuse, up to maxSpare
	root        counter[K]    // root.next is the most recent counter
	maxCounters int
	maxBans     int
	lockedUntil int64 // the shard is in lockdown before this time
	failures    uint64
	started     uint64
	refused     uint64
	evicted     uint64
	mu          sync.RWMutex
	_           [64]byte // keeps neighbouring shards' locks off one cache line
}

// New returns a Limiter configured by c.
func New[K comparable](c Config) (*Limiter[K], error) {
	if c.Threshold < 0 || c.Window < 0 || c.BanDuration < 0 || c.MaxBanDuration < 0 ||
		c.Cooldown < 0 || c.MaxPending < 0 || c.MaxBans < 0 || c.Shards < 0 {
		return nil, fmt.Errorf("%w: negative field in %+v", ErrInvalidConfig, c)
	}
	switch c.Full {
	case LockShard, EvictSoonest:
	default:
		return nil, fmt.Errorf("%w: unknown %v", ErrInvalidConfig, c.Full)
	}
	threshold := orDefault(c.Threshold, DefaultThreshold)
	if uint64(threshold) > math.MaxUint32 {
		return nil, fmt.Errorf("%w: Threshold %d exceeds the failure counts", ErrInvalidConfig, threshold)
	}
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
	capacity := orDefault(c.MaxPending, DefaultMaxPending)
	maxBans := orDefault(c.MaxBans, DefaultMaxBans)
	n := num.Shards(c.Shards, min(capacity, maxBans), runtime.GOMAXPROCS(0))
	l := &Limiter[K]{
		clock:     clock.New(c.Now),
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

func orDefault[T int | time.Duration](v, def T) T {
	if v == 0 {
		return def
	}
	return v
}

func (l *Limiter[K]) ready() bool {
	return l != nil && l.shards != nil
}

// read returns the current time in nanoseconds since New and the shard
// of key. It runs before any lock is taken, so a Now that blocks or calls
// back into the Limiter cannot deadlock it.
func (l *Limiter[K]) read(key K) (int64, *shard[K]) {
	t := l.clock.Mono()
	return t, l.shard(key)
}

func (l *Limiter[K]) shard(key K) *shard[K] {
	return &l.shards[maphash.Comparable(l.seed, key)&l.mask]
}

func (l *Limiter[K]) at(t int64) time.Time {
	return l.clock.At(t)
}

func (l *Limiter[K]) bucket(t int64) int64 {
	q := t / l.width
	if t%l.width != 0 && t < 0 {
		q--
	}
	return q
}

// Attempt is a reservation of one attempt for a key, made by
// Limiter.Attempt. Settle it exactly once with Fail, Release or Succeed,
// also when it was not allowed, where they do nothing; a reservation that
// is never settled keeps counting against its key until its counter is
// evicted. Copies of an Attempt share its reservation: once one of them
// is settled, settling another does nothing.
type Attempt[K comparable] struct {
	l       *Limiter[K]
	c       *counter[K]
	key     K
	gen     uint64        // of the reservation's slot
	slot    int           // in c.slots
	retry   time.Duration // of a refused attempt, from the time of refusal
	allowed bool
}

// Attempt reserves an attempt for key, such as a password check. The
// attempt is allowed if key is not banned and its failures within the
// window plus its attempts in flight are fewer than Threshold; then it
// counts as in flight until it is settled.
func (l *Limiter[K]) Attempt(key K) Attempt[K] {
	a := Attempt[K]{l: l, key: key}
	if !l.ready() {
		return a
	}
	t, s := l.read(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(l, t)
	until, refused := s.refusal(l, key, t)
	if !refused {
		if a.c = s.counter(key, l.bucket(t)); a.c == nil {
			until, refused = s.lockdown(), true
		}
	}
	if refused {
		s.refused++
		a.retry = time.Duration(max(until-t, 0))
		return a
	}
	a.slot, a.gen = a.c.reserve()
	a.allowed = true
	return a
}

// refusal reports whether key may not make an attempt at t, and until
// when it is banned; t itself if its attempts are all in flight.
func (s *shard[K]) refusal(l *Limiter[K], key K, t int64) (until int64, refused bool) {
	if r := s.bans[key]; r != nil && r.until > t {
		return r.until, true
	}
	if t < s.lockedUntil {
		return s.lockedUntil, true
	}
	c := s.counters[key]
	switch {
	case c == nil:
		return 0, false
	case c.waiting:
		return num.SatAdd(t, l.ban), true
	case c.count(l.bucket(t))+c.inflight >= l.threshold:
		return t, true // Threshold attempts are in flight: retry later
	default:
		return 0, false
	}
}

// Allowed reports whether the attempt may proceed.
func (a Attempt[K]) Allowed() bool {
	return a.allowed
}

// RetryAfter returns how long a refused attempt should wait before it is
// tried again, rounded up to a whole number of seconds as for an HTTP
// Retry-After header: until the ban that refused it ends, measured when
// it was refused, and at least a second, also when it was refused because
// the key's attempts were all in flight. It returns zero for an allowed
// attempt.
func (a Attempt[K]) RetryAfter() time.Duration {
	if a.allowed {
		return 0
	}
	d := max(a.retry, time.Second)
	if r := d % time.Second; r != 0 && d <= math.MaxInt64-time.Second {
		d += time.Second - r
	}
	return d
}

// Release settles an allowed attempt without a failure, such as a
// successful check of a key that the success does not prove is the
// caller's, or an attempt that was aborted. It leaves the key's earlier
// failures alone.
func (a Attempt[K]) Release() {
	a.settle(release)
}

// Succeed settles an allowed attempt as a success and clears the key's
// pending failures, as Limiter.Succeed does.
func (a Attempt[K]) Succeed() {
	a.settle(succeed)
}

// Fail settles an allowed attempt as a failure, as Limiter.Fail does, and
// returns the key's state afterwards. On an attempt that was not allowed,
// or was already settled, it does nothing and returns the zero Result.
func (a Attempt[K]) Fail() Result {
	return a.settle(fail)
}

type outcome int

const (
	release outcome = iota
	succeed
	fail
)

func (a Attempt[K]) settle(o outcome) Result {
	if !a.allowed {
		return Result{}
	}
	l := a.l
	t, s := l.read(a.key)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Only an unsettled reservation settles: its counter, also one that
	// was evicted or reset meanwhile, still holds its slot in the same
	// generation. A copy of a settled Attempt finds the generation
	// advanced, also once the counter is reused, and does nothing.
	if !a.c.release(a.slot, a.gen) {
		return Result{}
	}
	s.sweep(l, t)
	switch o {
	case release:
	case succeed:
		s.clear(a.key)
	case fail:
		return s.fail(l, a.key, t)
	}
	// Free a counter that holds nothing any more, so that attempts
	// settled at once never push out the counters of other keys.
	if c := s.counters[a.key]; c != nil && !c.waiting && c.idle(l.bucket(t)) {
		s.removeCounter(c)
	}
	return Result{}
}

// Fail records a failure of key and returns its state afterwards. A
// failure of a key that is already banned is not counted and does not
// extend the ban. Fail suits failures found without a reservation; around
// an expensive check use Attempt.
func (l *Limiter[K]) Fail(key K) Result {
	if !l.ready() {
		return Result{Banned: true}
	}
	t, s := l.read(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(l, t)
	return s.fail(l, key, t)
}

// fail counts a failure of key at t, unless it is banned, bans it at
// Threshold, and returns its state.
func (s *shard[K]) fail(l *Limiter[K], key K, t int64) Result {
	r := s.bans[key]
	if r != nil && r.until > t {
		return Result{Until: l.at(r.until), Offences: r.offences, Banned: true}
	}
	i := l.bucket(t)
	c := s.counter(key, i)
	if c == nil {
		return Result{Until: l.at(s.lockdown()), Banned: true}
	}
	c.add(i)
	s.failures++
	if c.waiting || c.count(i) >= l.threshold {
		if r == nil && !s.room(l, t) {
			// LockShard with every record an active ban: keep the
			// counter waiting for a record, and lock the shard
			// down until its earliest ban ends.
			if !c.waiting {
				c.unlink()
				c.waiting, c.queued = true, true
				s.waiting = append(s.waiting, c)
			}
			return Result{Until: l.at(s.lockdown()), Banned: true}
		}
		r = s.ban(l, key, r, c.offences, t)
		s.removeCounter(c)
		return Result{Until: l.at(r.until), Offences: r.offences, Banned: true, Started: true}
	}
	if t < s.lockedUntil {
		return Result{Until: l.at(s.lockedUntil), Banned: true}
	}
	return Result{}
}

// Ban bans b.Key until b.Until, for an administrator's ban or to restore
// the records that Bans returned before a restart. b.Offences, at least 1,
// is the key's number of bans in a row, so that its next ban is longer. A
// ban of the key that ends later, or with more offences, is kept as it
// is. A ban that has already ended is restored as a record in cooldown,
// which only makes the key's next ban longer, unless its cooldown has
// ended too, or the shard's ban table is full of active bans: then it is
// ignored. A ban in force drops the key's pending failures and attempts
// in flight; a record in cooldown leaves them alone. When the shard's ban
// table is full of active bans, Full decides for a ban in force:
// EvictSoonest makes room and LockShard returns ErrFull. The zero Limiter
// returns ErrUninitialized.
func (l *Limiter[K]) Ban(b Ban[K]) error {
	if !l.ready() {
		return ErrUninitialized
	}
	now, t := l.clock.Read()
	s := l.shard(b.Key)
	// The ban may come from another process, so its end is wall time.
	d := int64(b.Until.Round(0).Sub(now.Round(0)))
	if num.SatAdd(d, l.cooldown) <= 0 {
		return nil
	}
	until := num.SatAdd(t, d)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(l, t)
	r := s.bans[b.Key]
	active := until > t
	if r == nil {
		// A record in cooldown is not worth an active ban.
		if !active && len(s.bans) >= s.maxBans && s.heap[0].until > t {
			return nil
		}
		if !s.room(l, t) {
			return ErrFull
		}
		r = &record[K]{key: b.Key, index: len(s.heap)}
		s.bans[b.Key] = r
		s.heap = append(s.heap, r)
	}
	if r.until <= t && active {
		s.started++
	}
	r.until = max(r.until, until)
	r.offences = max(r.offences, b.Offences, 1)
	s.fix(r.index)
	// A ban in force drops the key's pending failures; a record in
	// cooldown only lengthens its next ban and leaves them alone.
	if c := s.counters[b.Key]; c != nil && r.until > t {
		s.removeCounter(c)
	}
	return nil
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
		victim := s.oldest()
		if victim == nil {
			return nil
		}
		s.removeCounter(victim)
	}
	c := s.newCounter(key, i)
	s.counters[key] = c
	c.linkAfter(&s.root)
	return c
}

// newCounter returns an empty counter for key, reusing a spare one.
func (s *shard[K]) newCounter(key K, i int64) *counter[K] {
	n := len(s.spare)
	if n == 0 {
		return &counter[K]{key: key, newest: i}
	}
	c := s.spare[n-1]
	s.spare[n-1] = nil
	s.spare = s.spare[:n-1]
	c.key, c.newest = key, i
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
	c := s.newCounter(r.key, i)
	c.offences = r.offences
	c.counts[uint64(i)%buckets] = uint32(min(l.threshold-1, math.MaxUint32))
	s.counters[r.key] = c
	c.linkAfter(&s.root)
}

// ban bans key from t, with its record r of earlier offences if any, or
// else prior offences, and returns its record. The caller made room for
// a new record.
func (s *shard[K]) ban(l *Limiter[K], key K, r *record[K], prior int, t int64) *record[K] {
	if r == nil {
		r = &record[K]{key: key, offences: prior, index: len(s.heap)}
		s.bans[key] = r
		s.heap = append(s.heap, r)
	}
	if r.offences < math.MaxInt {
		r.offences++
	}
	r.until = num.SatAdd(t, l.duration(r.offences))
	s.fix(r.index)
	s.started++
	return r
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
	t, s := l.read(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(l, t)
	s.clear(key)
}

// clear forgets key's pending failures.
func (s *shard[K]) clear(key K) {
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
// reported banned for one BanDuration from now: its ban is a first one,
// as a key with earlier offences still has its record and never waits.
func (l *Limiter[K]) BannedUntil(key K) (until time.Time, banned bool) {
	if !l.ready() {
		return time.Time{}, true
	}
	t, s := l.read(key)
	s.mu.RLock()
	defer s.mu.RUnlock()
	end, ok := s.bannedUntil(l, key, t)
	if !ok {
		return time.Time{}, false
	}
	return l.at(end), true
}

// bannedUntil reports whether key is banned at t and until when.
func (s *shard[K]) bannedUntil(l *Limiter[K], key K, t int64) (int64, bool) {
	if r := s.bans[key]; r != nil && r.until > t {
		return r.until, true
	}
	if t < s.lockedUntil {
		return s.lockedUntil, true
	}
	if c := s.counters[key]; c != nil && c.waiting {
		// Its ban starts when a record frees up.
		return num.SatAdd(t, l.ban), true
	}
	return 0, false
}

// Failures returns the number of key's failures counted in the current
// window, without attempts in flight. It is zero while BannedUntil
// reports key banned, also by a lockdown or while it waits for a ban
// record. It never changes the Limiter.
func (l *Limiter[K]) Failures(key K) int {
	if !l.ready() {
		return 0
	}
	t, s := l.read(key)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, banned := s.bannedUntil(l, key, t); banned {
		return 0
	}
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
	t, s := l.read(key)
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

// Reset lifts every ban and forgets every failure and reservation. It
// keeps the counters of Stats.
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
	t := l.clock.Mono()
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		s.sweep(l, t)
		s.mu.Unlock()
	}
}

// Bans returns the ban records, ordered by the time they end: the
// active bans, which end after now, and the ended bans whose offences are
// remembered for Cooldown. Pass each to Ban to restore them, such as
// after a restart.
func (l *Limiter[K]) Bans() []Ban[K] {
	if !l.ready() {
		return nil
	}
	t := l.clock.Mono()
	var list []Ban[K]
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.RLock()
		for _, r := range s.heap {
			if num.SatAdd(r.until, l.cooldown) > t {
				list = append(list, Ban[K]{Key: r.key, Until: l.at(r.until), Offences: r.offences})
			}
		}
		s.mu.RUnlock()
	}
	slices.SortFunc(list, func(a, b Ban[K]) int { return a.Until.Compare(b.Until) })
	return list
}

// Stats returns a snapshot of the Limiter's size and counters.
func (l *Limiter[K]) Stats() Stats {
	var st Stats
	if !l.ready() {
		return st
	}
	t := l.clock.Mono()
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.RLock()
		waiting := 0
		for _, c := range s.waiting {
			if c.waiting {
				waiting++
			}
		}
		st.Pending += len(s.counters) - waiting
		st.Waiting += waiting
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
		st.Failures += s.failures
		st.Started += s.started
		st.Refused += s.refused
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
	for c := s.oldest(); c != nil && c.idle(i); c = s.oldest() {
		s.removeCounter(c)
	}
	for len(s.heap) > 0 && num.SatAdd(s.heap[0].until, l.cooldown) <= t {
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

// oldest returns the least recently updated counter on the recency list,
// or nil if the list is empty.
func (s *shard[K]) oldest() *counter[K] {
	if c := s.root.prev; c != nil && c != &s.root {
		return c
	}
	return nil
}

// idle reports whether c holds nothing worth keeping at bucket i: no
// attempt in flight, no failure in the window, and no offences of an
// evicted ban that are younger than the window, which with Threshold 1
// come without a failure.
func (c *counter[K]) idle(i int64) bool {
	return c.inflight == 0 && c.count(i) == 0 && (c.offences == 0 || i-c.newest >= buckets)
}

// removeCounter forgets c; a stale entry of c in s.waiting is skipped.
func (s *shard[K]) removeCounter(c *counter[K]) {
	if c.prev != nil {
		c.unlink()
	}
	c.waiting = false
	delete(s.counters, c.key)
	if c.inflight > 0 {
		// Its reservations outlive it, so it is never reused: each
		// still settles once, against the key's current state.
		return
	}
	// Attempts made on c are all settled. Reuse keeps the slots, whose
	// generations only grow, so that copies of those Attempts stay
	// settled. A counter that s.waiting may point to is never reused.
	if !c.queued && len(s.spare) < maxSpare {
		*c = counter[K]{slots: c.slots, free: c.free}
		s.spare = append(s.spare, c)
	}
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
