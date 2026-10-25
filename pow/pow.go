// Package pow issues and verifies proof-of-work challenges that make each
// attempt at an expensive or abusable operation, such as a login, cost the
// client some CPU time.
//
// A server holds a Challenger with a secret key. Issue returns a challenge
// token that is signed with the key and bound to a caller-chosen context,
// such as the client's IP address and the form it is about to submit, so
// the server keeps no state per challenge. The client finds a solution with
// Solve, or with the same search in a browser, and sends it back with the
// token. Verify checks the work with a single SHA-256 hash before the
// signature, and accepts each challenge once: a bounded replay window
// remembers the nonces of the challenges it accepted until they expire.
//
//	c, err := pow.New(pow.Config{Key: key, Difficulty: 18})
//	token, err := c.Issue(clientIP, "login")          // server, sent to the client
//	solution, err := pow.Solve(ctx, token)            // client
//	err = c.Verify(token, solution, clientIP, "login") // server
//
// The binding is a list of strings, each length-prefixed in the MAC, so
// that ("ab", "c") and ("a", "bc") are different bindings.
//
// # Token and puzzle
//
// A token is the unpadded base64url encoding (RFC 4648 section 5) of 58
// bytes:
//
//	version (1, currently 1) | difficulty (1) | expiry (8, Unix milliseconds, big-endian)
//	| nonce (16) | HMAC-SHA-256 (32)
//
// The MAC covers a domain string, the first 26 bytes and the binding
// fields, each preceded by its length as a uvarint. A solution is a 64-bit
// number s such that SHA-256(token bytes || s as 8 big-endian bytes) starts
// with at least difficulty zero bits. Each extra bit doubles the expected
// work: difficulty d takes 2^d hashes on average.
//
// # Limits
//
// Proof of work raises the cost of each attempt; it does not stop an
// attacker with enough CPU, and it costs legitimate clients the same. Use
// it together with a failure limiter, and keep difficulty low enough for
// the slowest client that must log in.
//
// # Several servers
//
// Servers that share the key accept each other's challenges. To rotate
// the key, make the new one Config.Key and keep the old one in
// PreviousKeys for one TTL. Each
// Challenger records the challenges it accepted in a Store; the default,
// a MemoryStore, lives in process memory, so a solved challenge could be
// used once on each server and once more after a restart. Deployments
// with several instances should give them one shared Store, such as a
// key-value database with an atomic set-if-absent operation.
package pow

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"runtime"
	"time"

	"github.com/djylb/guard/internal/conf"
	"github.com/djylb/guard/internal/sign"
	"github.com/djylb/guard/replay"
)

// Version is the token format version this package issues and accepts.
const Version = 1

// Defaults of zero Config fields.
const (
	DefaultDifficulty     = 18
	DefaultTTL            = 2 * time.Minute
	DefaultSkew           = 2 * time.Second
	DefaultReplayCapacity = 1 << 16
)

// MinKeySize is the minimum length of Config.Key and PreviousKeys.
const MinKeySize = 16

const (
	headerLen = 1 + 1 + 8 + 16
	rawLen    = headerLen + sha256.Size
	// TokenLen is the length of a token string.
	TokenLen = (rawLen*8 + 5) / 6
)

const domain = "guard/pow/v1"

var (
	enc    = base64.RawURLEncoding
	strict = enc.Strict()
)

// Errors returned by Verify and Parse.
var (
	// ErrMalformed reports a token that cannot be decoded.
	ErrMalformed = errors.New("pow: malformed challenge")
	// ErrVersion reports a token of an unknown format version.
	ErrVersion = errors.New("pow: unsupported challenge version")
	// ErrExpired reports a challenge past its expiry.
	ErrExpired = errors.New("pow: challenge expired")
	// ErrNotYetValid reports a challenge that expires later than one
	// issued now would: issued by a server whose clock runs ahead by
	// more than the skew, or with a longer TTL.
	ErrNotYetValid = errors.New("pow: challenge issued in the future")
	// ErrInsufficientWork reports a solution that does not meet the
	// challenge's difficulty.
	ErrInsufficientWork = errors.New("pow: insufficient work")
	// ErrInvalidSignature reports a challenge not issued by this key for
	// this binding, or altered since.
	ErrInvalidSignature = errors.New("pow: invalid challenge signature")
	// ErrReplay reports a challenge that was already accepted.
	ErrReplay = errors.New("pow: challenge already used")
	// ErrStore wraps an error of a Store; the challenge is rejected.
	ErrStore = errors.New("pow: store failed")
	// ErrUninitialized reports a Challenger not created by New.
	ErrUninitialized = errors.New("pow: challenger not created by New")
	// ErrInvalidConfig reports a Config or argument that cannot be used.
	ErrInvalidConfig = errors.New("pow: invalid config")
)

// Config configures a Challenger.
type Config struct {
	// Now returns the current time. It defaults to time.Now.
	Now func() time.Time
	// Store records accepted challenges. It defaults to a MemoryStore
	// with ReplayCapacity entries.
	Store Store
	// Key is the HMAC key that signs challenges, at least MinKeySize
	// bytes and not all zero. Servers that verify each other's
	// challenges must share it. If it is nil, New generates a random
	// key, so challenges are valid only in this process. New copies it.
	Key []byte
	// PreviousKeys are keys that still verify but no longer sign, for
	// rotating Key: keep the old key here for one TTL.
	PreviousKeys [][]byte
	// Difficulty is the number of leading zero bits Issue asks for,
	// from 1 to 255. It defaults to DefaultDifficulty.
	Difficulty int
	// TTL is how long a challenge stays valid. It defaults to DefaultTTL.
	TTL time.Duration
	// Skew is how far ahead of this server's clock the clock of a server
	// that issued a challenge may run. It defaults to DefaultSkew.
	Skew time.Duration
	// ReplayCapacity is the capacity of the default Store: the number
	// of accepted challenges remembered until they expire. It defaults
	// to DefaultReplayCapacity. Once that many unexpired challenges
	// were accepted, older challenges are rejected early as expired.
	// Memory grows with use, to about 5 MiB at the default; a single
	// login form can use a few thousand. It is ignored when Store is set.
	ReplayCapacity int
}

// UnmarshalJSON reads a Config from a JSON object such as
//
//	{"key": "base64...", "difficulty": 18, "ttl": "2m", "skew": "2s"}
//
// with the fields key and previous_keys (standard base64), difficulty,
// ttl, skew and replay_capacity. Durations are strings in the form of
// time.ParseDuration. Fields that are absent keep their value; unknown
// fields and null values are an error. The key is required unless the
// Config already has one; "key": "random" asks for a key generated per
// process. Now and Store cannot be set from JSON.
func (c *Config) UnmarshalJSON(data []byte) error {
	v := struct {
		Key            conf.Key      `json:"key"`
		PreviousKeys   [][]byte      `json:"previous_keys"`
		TTL            conf.Duration `json:"ttl"`
		Skew           conf.Duration `json:"skew"`
		Difficulty     int           `json:"difficulty"`
		ReplayCapacity int           `json:"replay_capacity"`
	}{conf.Key{}, c.PreviousKeys, conf.Duration(c.TTL), conf.Duration(c.Skew), c.Difficulty, c.ReplayCapacity}
	if err := conf.Decode(data, &v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	key, err := v.Key.Resolve(c.Key)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	c.Key, c.PreviousKeys, c.TTL, c.Skew = key, v.PreviousKeys, time.Duration(v.TTL), time.Duration(v.Skew)
	c.Difficulty, c.ReplayCapacity = v.Difficulty, v.ReplayCapacity
	return nil
}

// Challenger issues and verifies challenges. It is safe for concurrent
// use. Its zero value is not usable: create one with New.
type Challenger struct {
	now        func() time.Time
	store      Store
	signer     *sign.Signer
	ttl        time.Duration
	skew       time.Duration
	difficulty uint8
}

// New returns a Challenger configured by c.
func New(c Config) (*Challenger, error) {
	signer, err := sign.New(domain, c.Key, c.PreviousKeys, MinKeySize)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	difficulty := c.Difficulty
	if difficulty == 0 {
		difficulty = DefaultDifficulty
	}
	if err := checkDifficulty(difficulty); err != nil {
		return nil, err
	}
	ttl := c.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl < time.Millisecond {
		return nil, fmt.Errorf("%w: TTL %v shorter than a millisecond", ErrInvalidConfig, ttl)
	}
	skew := c.Skew
	if skew == 0 {
		skew = DefaultSkew
	}
	if skew < 0 {
		return nil, fmt.Errorf("%w: negative skew %v", ErrInvalidConfig, skew)
	}
	if ttl > math.MaxInt64-skew {
		return nil, fmt.Errorf("%w: TTL %v plus skew %v overflows", ErrInvalidConfig, ttl, skew)
	}
	capacity := c.ReplayCapacity
	if capacity == 0 {
		capacity = DefaultReplayCapacity
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	store := c.Store
	if m, ok := store.(*MemoryStore); ok && m != nil && ttl+skew > m.window+m.skew {
		return nil, fmt.Errorf("%w: TTL %v plus skew %v exceeds the MemoryStore's window %v plus skew %v",
			ErrInvalidConfig, ttl, skew, m.window, m.skew)
	}
	if store == nil {
		m, err := NewMemoryStore(replay.Config{Now: now, Window: ttl, Skew: skew, Capacity: capacity})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
		store = m
	}
	return &Challenger{now: now, store: store, signer: signer, ttl: ttl, skew: skew, difficulty: uint8(difficulty)}, nil
}

func checkDifficulty(d int) error {
	if d < 1 || d > math.MaxUint8 {
		return fmt.Errorf("%w: difficulty %d outside 1..255", ErrInvalidConfig, d)
	}
	return nil
}

// Issue returns a new challenge at the configured difficulty, bound to
// the binding fields, such as the client's IP address and the operation.
// Verify accepts it only with the same fields in the same order.
func (c *Challenger) Issue(binding ...string) (string, error) {
	if c == nil || c.signer == nil {
		return "", ErrUninitialized
	}
	return c.issue(c.difficulty, binding), nil
}

// IssueDifficulty is Issue with a difficulty for this challenge, from 1
// to 255, for servers that raise the cost while under attack.
func (c *Challenger) IssueDifficulty(difficulty int, binding ...string) (string, error) {
	if c == nil || c.signer == nil {
		return "", ErrUninitialized
	}
	if err := checkDifficulty(difficulty); err != nil {
		return "", err
	}
	return c.issue(uint8(difficulty), binding), nil
}

func (c *Challenger) issue(difficulty uint8, binding []string) string {
	var raw [rawLen]byte
	raw[0] = Version
	raw[1] = difficulty
	binary.BigEndian.PutUint64(raw[2:10], uint64(c.now().Add(c.ttl).UnixMilli()))
	_, _ = rand.Read(raw[10:headerLen]) // crypto/rand.Read never fails
	mac := c.signer.Sign(raw[:headerLen], binding...)
	copy(raw[headerLen:], mac[:])
	return enc.EncodeToString(raw[:])
}

// Verify checks that solution solves token, that the challenge was issued
// with this Challenger's key, or one of its previous keys, for the
// binding fields and has not expired, and that it was not accepted
// before. It returns nil and remembers the challenge if all hold. A
// challenge rejected for any reason is not remembered, so a client may
// retry it with a correct solution.
//
// The errors are distinct for logs and metrics; answer the client alike
// for all of them, apart from asking for a new challenge.
func (c *Challenger) Verify(token string, solution uint64, binding ...string) error {
	if c == nil || c.signer == nil {
		return ErrUninitialized
	}
	raw, ch, err := decode(token)
	if err != nil {
		return err
	}
	now := c.now()
	nowMs := now.UnixMilli()
	exp := ch.Expires.UnixMilli()
	if exp < nowMs {
		return ErrExpired
	}
	if uint64(exp)-uint64(nowMs) > uint64((c.ttl+c.skew).Milliseconds())+1 {
		// Issued further ahead than the skew allows: by a server
		// whose clock runs ahead, or with a longer TTL.
		return ErrNotYetValid
	}
	if !meets(&raw, solution, ch.Difficulty) {
		return ErrInsufficientWork
	}
	if !c.signer.Verify(raw[headerLen:], raw[:headerLen], binding...) {
		return ErrInvalidSignature
	}
	fresh, err := c.store.MarkUsed(ch.Nonce, ch.Expires)
	switch {
	case err == nil && fresh:
		return nil
	case err == nil:
		return ErrReplay
	case errors.Is(err, ErrExpired), errors.Is(err, ErrNotYetValid):
		return err
	default:
		return fmt.Errorf("%w: %w", ErrStore, err)
	}
}

// ID identifies a challenge: its random nonce.
type ID [16]byte

// Store records the challenges a Challenger accepted, so that each is
// accepted only once, across every Challenger that shares the Store.
//
// Implementations must be safe for concurrent use and make MarkUsed
// atomic: of any number of concurrent or repeated calls with one id, on
// any instance, exactly one reports fresh, as with an atomic
// set-if-absent. They must remember an id at least until expires plus the
// largest amount by which the clock of a verifying server may lag, and
// return an error, never fresh, when they cannot tell. A Challenger calls
// MarkUsed only for authentic, solved, unexpired challenges, so its
// memory grows with accepted challenges alone, at most one per challenge
// issued within its TTL.
type Store interface {
	// MarkUsed records id as used until expires and reports whether it
	// was not recorded before. The error may be ErrExpired or
	// ErrNotYetValid, which Verify returns as they are; Verify wraps any
	// other error in ErrStore.
	MarkUsed(id ID, expires time.Time) (fresh bool, err error)
}

// MemoryStore is a Store in process memory, backed by a replay.Window. It
// is the default Store, and can be shared by Challengers in one process,
// for example while rotating keys.
type MemoryStore struct {
	w      *replay.Window
	window time.Duration
	skew   time.Duration
}

// NewMemoryStore returns a MemoryStore configured by c, where c.Window is
// the TTL of the challenges it records and c.Skew how far ahead their
// issuers' clocks may run. Challengers with different TTLs may share it as
// long as TTL plus Skew of each is at most c.Window plus c.Skew; New
// rejects a Challenger that exceeds it.
func NewMemoryStore(c replay.Config) (*MemoryStore, error) {
	w, err := replay.New(c)
	if err != nil {
		return nil, err
	}
	return &MemoryStore{w: w, window: c.Window, skew: c.Skew}, nil
}

// Stats returns the use of the store's replay window.
func (m *MemoryStore) Stats() replay.Stats {
	return m.w.Stats()
}

// MarkUsed implements Store. When the window is full, it reports the
// oldest challenges as expired (see replay.ShrinkWindow).
func (m *MemoryStore) MarkUsed(id ID, expires time.Time) (bool, error) {
	err := m.w.Check(expires.Add(-m.window), id[:])
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, replay.ErrReplay):
		return false, nil
	case errors.Is(err, replay.ErrStale):
		return false, ErrExpired
	case errors.Is(err, replay.ErrFuture):
		return false, ErrNotYetValid
	default:
		return false, err
	}
}

// Difficulty returns the difficulty Issue asks for.
func (c *Challenger) Difficulty() int {
	if c == nil {
		return 0
	}
	return int(c.difficulty)
}

// Challenge is the public content of a challenge token.
type Challenge struct {
	// Expires is when the challenge stops being accepted.
	Expires time.Time
	// Nonce makes each challenge unique and identifies it in a Store.
	Nonce ID
	// Version is the token format version.
	Version uint8
	// Difficulty is the number of leading zero bits a solution needs.
	Difficulty uint8
}

// Parse decodes a token without checking its signature, for clients that
// want to show the difficulty or expiry.
func Parse(token string) (Challenge, error) {
	_, ch, err := decode(token)
	return ch, err
}

func decode(token string) ([rawLen]byte, Challenge, error) {
	var raw [rawLen]byte
	if len(token) != TokenLen {
		return raw, Challenge{}, ErrMalformed
	}
	var src [TokenLen]byte
	copy(src[:], token)
	if n, err := strict.Decode(raw[:], src[:]); err != nil || n != rawLen {
		return raw, Challenge{}, ErrMalformed
	}
	if raw[0] != Version {
		return raw, Challenge{}, ErrVersion
	}
	exp := binary.BigEndian.Uint64(raw[2:10])
	if raw[1] == 0 || exp > math.MaxInt64 {
		return raw, Challenge{}, ErrMalformed
	}
	ch := Challenge{
		Expires:    time.UnixMilli(int64(exp)),
		Version:    raw[0],
		Difficulty: raw[1],
	}
	copy(ch.Nonce[:], raw[10:headerLen])
	return raw, ch, nil
}

// Check reports whether solution solves token, without checking the
// token's signature or expiry.
func Check(token string, solution uint64) (bool, error) {
	raw, ch, err := decode(token)
	if err != nil {
		return false, err
	}
	return meets(&raw, solution, ch.Difficulty), nil
}

// Solve searches for a solution of token, trying 0, 1, 2 and so on, until
// it finds one or ctx is done. The expected number of hashes is 2 to the
// power of the challenge's difficulty.
func Solve(ctx context.Context, token string) (uint64, error) {
	raw, ch, err := decode(token)
	if err != nil {
		return 0, err
	}
	var buf [rawLen + 8]byte
	copy(buf[:], raw[:])
	for s := uint64(0); ; s++ {
		if s&0xffff == 0 {
			// Yield so that timers, such as ctx's deadline, run
			// even on a single thread without preemption.
			runtime.Gosched()
			if err := ctx.Err(); err != nil {
				return 0, err
			}
		}
		binary.BigEndian.PutUint64(buf[rawLen:], s)
		sum := sha256.Sum256(buf[:])
		if leadingZeros(&sum) >= int(ch.Difficulty) {
			return s, nil
		}
		if s == math.MaxUint64 {
			return 0, ErrInsufficientWork
		}
	}
}

func meets(raw *[rawLen]byte, solution uint64, difficulty uint8) bool {
	var buf [rawLen + 8]byte
	copy(buf[:], raw[:])
	binary.BigEndian.PutUint64(buf[rawLen:], solution)
	sum := sha256.Sum256(buf[:])
	return leadingZeros(&sum) >= int(difficulty)
}

func leadingZeros(sum *[sha256.Size]byte) int {
	n := 0
	for i := 0; i < len(sum); i += 8 {
		w := binary.BigEndian.Uint64(sum[i:])
		if w != 0 {
			return n + bits.LeadingZeros64(w)
		}
		n += 64
	}
	return n
}
