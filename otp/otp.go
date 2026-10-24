// Package otp implements HOTP (RFC 4226) and TOTP (RFC 6238) one-time
// passwords, as used by authenticator apps for two-factor login.
//
// A Key holds the shared secret and parameters. GenerateSecret creates a
// secret, Key.URI builds the otpauth:// URI that authenticator apps import
// (render it as a QR code with a library of your choice), and ParseURI
// reads one back.
//
// # Replay protection
//
// A one-time password must be accepted only once. Verify therefore takes
// the account's next acceptable time step and returns the one to store
// after a successful login:
//
//	next, err := key.Verify(code, time.Now(), account.NextStep)
//	if err != nil {
//		return err // ErrCodeMismatch, ErrCodeReused, ErrCodeFormat, ...
//	}
//	account.NextStep = next // persist, atomically with the check
//
// A fresh account starts with NextStep 0. Two concurrent logins must not
// both pass with the same code: store the new value with a compare-and-swap
// on the old one, or serialise logins per account. VerifyCounter does the
// same for HOTP counters. There is deliberately no check that ignores
// replays.
//
// Codes are compared in constant time, and Verify accepts only codes of
// exactly Digits ASCII digits.
//
// # Guessing
//
// A six-digit code is guessed with probability 2·Skew+1 in a million per
// try. Limit tries per account and per client, for example with a
// failban.Limiter, and answer every rejected code alike: telling
// ErrCodeReused from ErrCodeMismatch confirms to an attacker that a
// code was right.
package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"time"
)

// Errors returned by this package.
var (
	// ErrCodeFormat reports a code that is not exactly Digits ASCII
	// digits.
	ErrCodeFormat = errors.New("otp: malformed code")
	// ErrCodeMismatch reports a code that matches no acceptable step or
	// counter.
	ErrCodeMismatch = errors.New("otp: incorrect code")
	// ErrCodeReused reports a code that matches a time step that was
	// already used: a replay, or a second login within one period.
	ErrCodeReused = errors.New("otp: code already used")
	// ErrInvalidKey reports a Key whose parameters cannot be used.
	ErrInvalidKey = errors.New("otp: invalid key")
	// ErrInvalidSecret reports a secret that is not valid base32.
	ErrInvalidSecret = errors.New("otp: invalid base32 secret")
	// ErrInvalidURI reports an otpauth URI that cannot be parsed.
	ErrInvalidURI = errors.New("otp: invalid otpauth URI")
	// ErrInvalidTime reports a time before the Unix epoch.
	ErrInvalidTime = errors.New("otp: time before the Unix epoch")
)

// Algorithm is the HMAC hash function of a Key.
type Algorithm int

// The algorithms of RFC 6238. SHA1 is the default and the only one that
// every authenticator app supports.
const (
	SHA1 Algorithm = iota
	SHA256
	SHA512
)

// String returns the algorithm's name as written in otpauth URIs.
func (a Algorithm) String() string {
	switch a {
	case SHA1:
		return "SHA1"
	case SHA256:
		return "SHA256"
	case SHA512:
		return "SHA512"
	default:
		return fmt.Sprintf("Algorithm(%d)", int(a))
	}
}

func (a Algorithm) hash() func() hash.Hash {
	switch a {
	case SHA1:
		return sha1.New
	case SHA256:
		return sha256.New
	case SHA512:
		return sha512.New
	default:
		return nil
	}
}

// Kind is the type of one-time password a Key is used for, as recorded in
// its otpauth URI.
type Kind int

// The kinds of one-time password.
const (
	TOTP Kind = iota // time-based, RFC 6238
	HOTP             // counter-based, RFC 4226
)

// String returns the kind's name as written in otpauth URIs.
func (k Kind) String() string {
	switch k {
	case TOTP:
		return "totp"
	case HOTP:
		return "hotp"
	default:
		return fmt.Sprintf("Kind(%d)", int(k))
	}
}

// Limits and defaults.
const (
	// MinSecretSize is the shortest secret RFC 4226 allows, in bytes.
	MinSecretSize = 16
	// MinLegacySecretSize is the shortest secret accepted with
	// Key.AllowShortSecret: 80 bits, as some systems generated.
	MinLegacySecretSize = 10
	// DefaultSecretSize is the secret size RFC 4226 recommends, in
	// bytes.
	DefaultSecretSize = 20
	// DefaultDigits is the code length most apps expect.
	DefaultDigits = 6
	// MinDigits is the shortest code RFC 4226 allows.
	MinDigits = 6
	// MaxDigits is the longest code that carries information: the
	// truncated HMAC is a 31-bit number.
	MaxDigits = 10
	// DefaultPeriod is the TOTP time step most apps expect.
	DefaultPeriod = 30 * time.Second
)

// Key is a one-time password secret with its parameters. Zero Digits and
// Period select the defaults. A Key is safe for concurrent use as long as
// it is not modified.
type Key struct {
	// Issuer names the service, shown by authenticator apps.
	Issuer string
	// Account names the user, shown by authenticator apps.
	Account string
	// Secret is the shared secret, at least MinSecretSize bytes.
	Secret []byte
	// Period is the TOTP time step, a whole number of seconds. It
	// defaults to DefaultPeriod.
	Period time.Duration
	// Digits is the code length, from MinDigits to MaxDigits. It
	// defaults to DefaultDigits.
	Digits int
	// Skew is the number of time steps before and after the current
	// one that Verify also accepts, to tolerate clock drift and typing
	// time; 1 is common. For VerifyCounter it is the number of counters
	// after the expected one that are accepted, to resynchronise a
	// token whose button was pressed without logging in. Each extra
	// step costs an HMAC per verification and raises the chance that a
	// guess matches, so keep it small.
	Skew uint
	// Counter is the initial HOTP counter of an otpauth URI.
	Counter uint64
	// Algorithm is the HMAC hash function. It defaults to SHA1.
	Algorithm Algorithm
	// AllowShortSecret accepts secrets from MinLegacySecretSize bytes,
	// below the RFC minimum, for accounts enrolled elsewhere with 80-bit
	// secrets. Re-enrol such accounts when possible. ParseURI never sets
	// it: for such a URI, build the Key from DecodeSecret.
	AllowShortSecret bool
	// Kind is the URI type: TOTP or HOTP. It only affects URI.
	Kind Kind
}

// GenerateSecret returns a random secret of size bytes; DefaultSecretSize
// is a good choice, or the hash size for SHA256 and SHA512 keys.
func GenerateSecret(size int) ([]byte, error) {
	if size < MinSecretSize {
		return nil, fmt.Errorf("%w: secret size %d below %d", ErrInvalidKey, size, MinSecretSize)
	}
	b := make([]byte, size)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return b, nil
}

// params validates k and returns its effective digits and period.
func (k *Key) params() (digits int, period uint64, err error) {
	if k == nil {
		return 0, 0, fmt.Errorf("%w: nil key", ErrInvalidKey)
	}
	minSize := MinSecretSize
	if k.AllowShortSecret {
		minSize = MinLegacySecretSize
	}
	if len(k.Secret) < minSize {
		return 0, 0, fmt.Errorf("%w: secret of %d bytes, need at least %d", ErrInvalidKey, len(k.Secret), minSize)
	}
	if k.Algorithm.hash() == nil {
		return 0, 0, fmt.Errorf("%w: unknown %v", ErrInvalidKey, k.Algorithm)
	}
	digits = k.Digits
	if digits == 0 {
		digits = DefaultDigits
	}
	if digits < MinDigits || digits > MaxDigits {
		return 0, 0, fmt.Errorf("%w: %d digits outside %d..%d", ErrInvalidKey, digits, MinDigits, MaxDigits)
	}
	p := k.Period
	if p == 0 {
		p = DefaultPeriod
	}
	if p < time.Second || p%time.Second != 0 {
		return 0, 0, fmt.Errorf("%w: period %v is not a positive whole number of seconds", ErrInvalidKey, p)
	}
	return digits, uint64(p / time.Second), nil
}

// Validate reports whether k's parameters can be used.
func (k *Key) Validate() error {
	_, _, err := k.params()
	return err
}

// Step returns the TOTP time step that contains t.
func (k *Key) Step(t time.Time) (uint64, error) {
	_, period, err := k.params()
	if err != nil {
		return 0, err
	}
	return step(t, period)
}

func step(t time.Time, period uint64) (uint64, error) {
	u := t.Unix()
	if u < 0 {
		return 0, ErrInvalidTime
	}
	return uint64(u) / period, nil
}

// Code returns the TOTP code for time t.
func (k *Key) Code(t time.Time) (string, error) {
	digits, period, err := k.params()
	if err != nil {
		return "", err
	}
	s, err := step(t, period)
	if err != nil {
		return "", err
	}
	g := k.newGenerator(digits)
	return string(g.code(s)), nil
}

// CounterCode returns the HOTP code for counter.
func (k *Key) CounterCode(counter uint64) (string, error) {
	digits, _, err := k.params()
	if err != nil {
		return "", err
	}
	g := k.newGenerator(digits)
	return string(g.code(counter)), nil
}

// Verify checks a TOTP code at time t. It accepts the code of the current
// time step and of Skew steps on either side, but none below next, the
// value Verify returned for the account's previous successful code (0 for
// a fresh account). On success it returns the value to store as the
// account's next acceptable step.
//
// A correct code for a step below next returns ErrCodeReused. If a code
// matches several steps by chance, the latest acceptable one is used.
func (k *Key) Verify(code string, t time.Time, next uint64) (uint64, error) {
	digits, period, err := k.params()
	if err != nil {
		return next, err
	}
	if !wellFormed(code, digits) {
		return next, ErrCodeFormat
	}
	cur, err := step(t, period)
	if err != nil {
		return next, err
	}
	lo := cur - min(cur, uint64(k.Skew))
	hi := cur + min(math.MaxUint64-1-cur, uint64(k.Skew)) // cur < MaxUint64
	return k.verify(code, digits, lo, hi, next)
}

// VerifyCounter checks an HOTP code against counters next to next+Skew,
// where next is the value VerifyCounter returned for the token's previous
// successful code, or the initial counter. On success it returns the value
// to store as the token's next counter.
func (k *Key) VerifyCounter(code string, next uint64) (uint64, error) {
	digits, _, err := k.params()
	if err != nil {
		return next, err
	}
	if !wellFormed(code, digits) {
		return next, ErrCodeFormat
	}
	// The last counter is never accepted, so that the returned next
	// counter is always greater than the one used.
	if next == math.MaxUint64 {
		return next, ErrCodeMismatch
	}
	hi := next + min(math.MaxUint64-1-next, uint64(k.Skew))
	return k.verify(code, digits, next, hi, next)
}

// verify compares code with the codes of steps lo to hi, all of them, in
// constant time per step.
func (k *Key) verify(code string, digits int, lo, hi, next uint64) (uint64, error) {
	g := k.newGenerator(digits)
	want := []byte(code)
	matched, reused := false, false
	var accept uint64
	for s := lo; ; s++ {
		if subtle.ConstantTimeCompare(g.code(s), want) == 1 {
			if s >= next {
				matched, accept = true, s
			} else {
				reused = true
			}
		}
		if s == hi {
			break
		}
	}
	switch {
	case matched:
		return accept + 1, nil
	case reused:
		return next, ErrCodeReused
	default:
		return next, ErrCodeMismatch
	}
}

func wellFormed(code string, digits int) bool {
	if len(code) != digits {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}

var pow10 = [MaxDigits + 1]uint64{1, 10, 100, 1e3, 1e4, 1e5, 1e6, 1e7, 1e8, 1e9, 1e10}

// generator computes codes with one reusable HMAC.
type generator struct {
	mac    hash.Hash
	sum    [sha512.Size]byte
	out    [MaxDigits]byte
	digits int
}

func (k *Key) newGenerator(digits int) *generator {
	return &generator{mac: hmac.New(k.Algorithm.hash(), k.Secret), digits: digits}
}

// code returns the code for counter c, valid until the next call.
func (g *generator) code(c uint64) []byte {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], c)
	g.mac.Reset()
	g.mac.Write(msg[:])
	sum := g.mac.Sum(g.sum[:0])
	off := sum[len(sum)-1] & 0x0f
	v := uint64(binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff)
	v %= pow10[g.digits]
	out := g.out[:g.digits]
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = byte('0' + v%10)
		v /= 10
	}
	return out
}
