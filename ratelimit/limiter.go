package ratelimit

import (
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"math/bits"
	"sync"
	"time"

	"github.com/djylb/guard/internal/conf"
)

const (
	// Shards is the number of independently locked shards of a Limiter.
	Shards = 64
	// DefaultCapacity is the capacity of a Limiter whose Config leaves it
	// zero.
	DefaultCapacity = 65536
	// MaxCapacity is the largest Capacity a Config may ask for.
	MaxCapacity = 1 << 30

	shardShift = 64 - 6 // the top six bits of the hash pick the shard
	startNodes = 16
)

// ErrInvalidConfig reports a Config that New cannot use.
var ErrInvalidConfig = errors.New("ratelimit: invalid config")

// Config configures a Limiter. Its zero value is valid.
type Config struct {
	// Capacity is the total number of keys held, split evenly across the
	// shards: each holds Capacity/Shards keys, at least one. 0 means
	// DefaultCapacity; there is no unlimited setting. A negative value or
	// one above MaxCapacity is an error. Memory grows with the keys, by
	// about 48 bytes and the key's own bytes each, plus 4 bytes per
	// capacity slot for the hash index.
	Capacity int
}

type jsonConfig struct {
	Capacity int `json:"capacity"`
}

// UnmarshalJSON reads a Config from a JSON object such as
//
//	{"capacity": 65536}
//
// Absent fields keep their value; unknown, repeated and null fields are an
// error, and names must match exactly.
//
//goland:noinspection GoMixedReceiverTypes
func (c *Config) UnmarshalJSON(data []byte) error {
	v := jsonConfig{Capacity: c.Capacity}
	if err := conf.Decode(data, &v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	c.Capacity = v.Capacity
	return nil
}

// MarshalJSON writes c in the form UnmarshalJSON reads.
//
//goland:noinspection GoMixedReceiverTypes
func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonConfig(c))
}

type rateJSON struct {
	Per   float64 `json:"per"`
	Burst int     `json:"burst"`
}

// UnmarshalJSON reads a Rate from a JSON object such as
//
//	{"per": 5, "burst": 10}
//
// Absent fields keep their value; unknown, repeated and null fields are an
// error, and names must match exactly.
//
//goland:noinspection GoMixedReceiverTypes
func (r *Rate) UnmarshalJSON(data []byte) error {
	v := rateJSON{Per: r.Per, Burst: r.Burst}
	if err := conf.Decode(data, &v); err != nil {
		return fmt.Errorf("ratelimit: invalid rate: %w", err)
	}
	r.Per, r.Burst = v.Per, v.Burst
	return nil
}

// MarshalJSON writes r in the form UnmarshalJSON reads.
//
//goland:noinspection GoMixedReceiverTypes
func (r Rate) MarshalJSON() ([]byte, error) {
	return json.Marshal(rateJSON(r))
}

// Limiter limits events per string key. It is safe for concurrent use.
// Create it with New: the zero Limiter refuses every request.
type Limiter struct {
	origin time.Time
	shards []shard
	seed   maphash.Seed
}

// shard is an LRU of keys over a slab of nodes, indexed by a chained hash
// table of fixed size. Node indexes are 1-based; 0 means none.
type shard struct {
	buckets []int32 // hash & mask -> first node of the chain
	nodes   []node  // nodes[0] is unused
	mu      sync.Mutex
	mask    uint64
	limit   int   // keys held at most
	head    int32 // most recently used
	tail    int32 // least recently used
	_       [64]byte
}

type node struct {
	key        string
	hash       uint64
	g          GCRA
	prev, next int32 // LRU, towards head and towards tail
	chain      int32 // next node in the same bucket
}

// New returns a Limiter for the Config.
func New(c Config) (*Limiter, error) {
	capacity := c.Capacity
	switch {
	case capacity == 0:
		capacity = DefaultCapacity
	case capacity < 0 || capacity > MaxCapacity:
		return nil, fmt.Errorf("%w: capacity %d", ErrInvalidConfig, c.Capacity)
	}
	per := max(capacity/Shards, 1)
	size := 1 << bits.Len(uint(per-1)) // a power of two, at least per
	l := &Limiter{seed: maphash.MakeSeed(), origin: time.Now(), shards: make([]shard, Shards)}
	for i := range l.shards {
		s := &l.shards[i]
		s.limit = per
		s.buckets = make([]int32, size)
		s.mask = uint64(size - 1) //nolint:gosec // G115: size is a positive power of two
		s.nodes = make([]node, 1, min(per+1, startNodes))
	}
	return l, nil
}

// usable reports whether l came from New.
func (l *Limiter) usable() bool { return l != nil && len(l.shards) == Shards }

// offset returns now in nanoseconds since the Limiter's origin.
func (l *Limiter) offset(now time.Time) int64 { return int64(now.Sub(l.origin)) }

// lock returns the locked shard of key and its node, adding the key if it
// is new.
func (l *Limiter) lock(key string) (*shard, int32) {
	h := maphash.String(l.seed, key)
	s := &l.shards[h>>shardShift]
	s.mu.Lock()
	return s, s.get(key, h)
}

// Allow takes n units of key at now under the rate r. It reports whether
// they are admitted; if not, wait is the time until they would be (see the
// package documentation for n > r.Burst and other edge cases). A refusal
// leaves the key's debt unchanged. An unlimited rate admits everything and
// keeps no state; a Limiter that was not made by New admits nothing.
// Allow does not allocate, apart from adding a key to a table that is
// still growing; the Limiter keeps the key string, which the caller must
// not modify.
func (l *Limiter) Allow(key string, r Rate, n int, now time.Time) (ok bool, wait time.Duration) {
	if !l.usable() {
		return false, 0
	}
	interval, burst, kind := r.limit()
	switch {
	case kind == rateUnlimited:
		return n >= 0, 0
	case kind == rateInvalid:
		return false, forever
	case n < 0:
		return false, 0
	}
	t := l.offset(now)
	s, i := l.lock(key)
	ok, wait = s.nodes[i].g.take(t, interval, burst, n)
	s.mu.Unlock()
	return ok, wait
}

// Penalize charges n units of key at now without refusing. It does
// nothing for an unlimited or invalid rate, for n <= 0 and on a Limiter
// that was not made by New.
func (l *Limiter) Penalize(key string, r Rate, n int, now time.Time) {
	if !l.usable() || n <= 0 {
		return
	}
	interval, _, kind := r.limit()
	if kind != rateLimited {
		return
	}
	t := l.offset(now)
	s, i := l.lock(key)
	s.nodes[i].g.charge(t, interval, n)
	s.mu.Unlock()
}

// Len returns the number of keys held.
func (l *Limiter) Len() int {
	if !l.usable() {
		return 0
	}
	n := 0
	for i := range l.shards {
		s := &l.shards[i]
		s.mu.Lock()
		n += len(s.nodes) - 1
		s.mu.Unlock()
	}
	return n
}

// get returns the node of key, moved to the front of the LRU, adding it
// with a fresh state, in place of the least recently used key when the
// shard is full. The caller holds s.mu.
func (s *shard) get(key string, h uint64) int32 {
	b := h & s.mask
	for i := s.buckets[b]; i != 0; i = s.nodes[i].chain {
		if n := &s.nodes[i]; n.hash == h && n.key == key {
			s.toFront(i)
			return i
		}
	}
	var i int32
	if len(s.nodes) <= s.limit {
		if len(s.nodes) == cap(s.nodes) {
			grown := make([]node, len(s.nodes), min(2*cap(s.nodes), s.limit+1))
			copy(grown, s.nodes)
			s.nodes = grown
		}
		i = int32(len(s.nodes)) //nolint:gosec // limit <= MaxCapacity/Shards
		s.nodes = append(s.nodes, node{})
	} else {
		i = s.tail
		s.unlink(i)
		s.unchain(i)
	}
	s.nodes[i] = node{key: key, hash: h, chain: s.buckets[b]}
	s.buckets[b] = i
	s.pushFront(i)
	return i
}

// toFront makes i the most recently used node.
func (s *shard) toFront(i int32) {
	if s.head != i {
		s.unlink(i)
		s.pushFront(i)
	}
}

func (s *shard) pushFront(i int32) {
	n := &s.nodes[i]
	n.prev, n.next = 0, s.head
	if s.head != 0 {
		s.nodes[s.head].prev = i
	}
	s.head = i
	if s.tail == 0 {
		s.tail = i
	}
}

func (s *shard) unlink(i int32) {
	n := &s.nodes[i]
	if n.prev != 0 {
		s.nodes[n.prev].next = n.next
	} else {
		s.head = n.next
	}
	if n.next != 0 {
		s.nodes[n.next].prev = n.prev
	} else {
		s.tail = n.prev
	}
}

// unchain removes node i from its hash chain.
func (s *shard) unchain(i int32) {
	b := s.nodes[i].hash & s.mask
	if s.buckets[b] == i {
		s.buckets[b] = s.nodes[i].chain
		return
	}
	for j := s.buckets[b]; j != 0; j = s.nodes[j].chain {
		if s.nodes[j].chain == i {
			s.nodes[j].chain = s.nodes[i].chain
			return
		}
	}
}
