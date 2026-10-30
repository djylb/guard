// Package sign computes domain-separated HMAC-SHA-256 tags over a fixed
// header and length-prefixed fields, with a current key that signs and
// previous keys that still verify, so that keys can be rotated. Signing
// and verifying do not allocate.
//
// It also holds the one format of the guard packages' signed tokens: a
// fixed-size header that ends with a random nonce, followed by the tag of
// the header, encoded as unpadded base64url with strict decoding, so that
// each token has a single spelling.
package sign

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sync"
)

// Size is the length of a tag.
const Size = sha256.Size

// NonceSize is the length of the random nonce that ends a token header.
const NonceSize = 16

// MaxRaw is the largest decoded token Open accepts.
const MaxRaw = 64

var (
	enc    = base64.RawURLEncoding
	strict = enc.Strict()
)

// TokenLen returns the length of the token string of a raw token of n
// bytes: header and tag.
func TokenLen(n int) int {
	return enc.EncodedLen(n)
}

// maxPooled is the largest message buffer kept in a pool.
const maxPooled = 4096

// Signer signs with its first key and verifies with all of them. It is
// safe for concurrent use.
type Signer struct {
	domain string
	keys   []*keyPool // keys[0] signs
}

type keyPool struct {
	pool sync.Pool // of *state
}

// state is a pooled HMAC with a message buffer, so that nothing passed to
// the hash escapes from the caller's stack.
type state struct {
	h   hash.Hash
	msg []byte
	sum [Size]byte
}

// New returns a Signer for domain with key and the previous keys. A nil
// key generates a random one, valid only in this process; then previous
// must be empty. Keys must be at least minSize bytes and not all zero;
// they are copied.
func New(domain string, key []byte, previous [][]byte, minSize int) (*Signer, error) {
	if key == nil {
		if len(previous) > 0 {
			return nil, errors.New("previous keys without a key")
		}
		key = make([]byte, 32)
		_, _ = rand.Read(key) // crypto/rand.Read never fails
	}
	s := &Signer{domain: domain}
	for i, k := range append([][]byte{key}, previous...) {
		if len(k) < minSize {
			return nil, fmt.Errorf("key %d shorter than %d bytes", i, minSize)
		}
		if allZero(k) {
			return nil, fmt.Errorf("key %d is all zero", i)
		}
		k = append([]byte(nil), k...)
		p := &keyPool{}
		p.pool.New = func() any { return &state{h: hmac.New(sha256.New, k)} }
		s.keys = append(s.keys, p)
	}
	return s, nil
}

// Sign returns the tag of header and fields under the current key.
func (s *Signer) Sign(header []byte, fields ...string) [Size]byte {
	return s.keys[0].tag(s.domain, header, fields)
}

// Verify reports whether tag is the tag of header and fields under any
// of the keys. It compares in constant time and tries every key.
func (s *Signer) Verify(tag, header []byte, fields ...string) bool {
	ok := 0
	for _, k := range s.keys {
		sum := k.tag(s.domain, header, fields)
		ok |= subtle.ConstantTimeCompare(sum[:], tag)
	}
	return ok == 1
}

func (p *keyPool) tag(domain string, header []byte, fields []string) [Size]byte {
	st, _ := p.pool.Get().(*state)
	m := append(st.msg[:0], domain...)
	m = append(m, 0)
	m = append(m, header...)
	for _, f := range fields {
		m = binary.AppendUvarint(m, uint64(len(f)))
		m = append(m, f...)
	}
	st.msg = m
	st.h.Reset()
	st.h.Write(m)
	st.h.Sum(st.sum[:0])
	sum := st.sum
	if cap(m) <= maxPooled { // do not pool huge buffers
		p.pool.Put(st)
	}
	return sum
}

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// Seal completes and encodes a raw token: raw holds the header, whose
// last NonceSize bytes Seal fills from crypto/rand, followed by Size
// bytes for the tag of the header and fields.
func (s *Signer) Seal(raw []byte, fields ...string) string {
	h := len(raw) - Size
	_, _ = rand.Read(raw[h-NonceSize : h]) // crypto/rand.Read never fails
	tag := s.Sign(raw[:h], fields...)
	copy(raw[h:], tag[:])
	return enc.EncodeToString(raw)
}

// Open decodes token into raw, which must be at most MaxRaw bytes long,
// and reports whether token is the strict encoding of exactly len(raw)
// bytes. It does not check the tag; see Check.
func Open(raw []byte, token string) bool {
	if len(raw) > MaxRaw || len(token) != enc.EncodedLen(len(raw)) {
		return false
	}
	// Decode from a stack copy, so that the string does not escape.
	var src [(MaxRaw*8 + 5) / 6]byte
	n := copy(src[:], token)
	got, err := strict.Decode(raw, src[:n])
	return err == nil && got == len(raw)
}

// Check reports whether the tag at the end of raw, as Seal wrote it, is
// the tag of the header and fields under any of the keys.
func (s *Signer) Check(raw []byte, fields ...string) bool {
	h := len(raw) - Size
	return h >= 0 && s.Verify(raw[h:], raw[:h], fields...)
}
