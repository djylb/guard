package webguard

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
	"mime"
	"net/http"
	"sync"
	"time"
)

// Errors of CSRF tokens.
var (
	// ErrCSRFToken reports a missing, malformed, expired or forged CSRF
	// token, or one issued for another session.
	ErrCSRFToken = errors.New("webguard: invalid CSRF token")
	// ErrNoSession reports an empty session identifier.
	ErrNoSession = errors.New("webguard: no session for CSRF token")
	// ErrUninitialized reports a Guard or CSRF not created by New or
	// NewCSRF. Their zero values reject every request with it.
	ErrUninitialized = errors.New("webguard: not created by New or NewCSRF")
)

// Defaults of CSRFConfig.
const (
	DefaultCSRFMaxAge = 12 * time.Hour
	DefaultCSRFHeader = "X-CSRF-Token"
	DefaultCSRFField  = "csrf_token"
	// MinCSRFKeySize is the minimum length of CSRFConfig.Key.
	MinCSRFKeySize = 16
)

const (
	csrfVersion   = 1
	csrfHeaderLen = 1 + 8 + 16
	csrfRawLen    = csrfHeaderLen + sha256.Size
	// CSRFTokenLen is the length of a CSRF token string.
	CSRFTokenLen = (csrfRawLen*8 + 5) / 6
	// csrfClockSkew tolerates tokens issued by servers whose clocks run
	// slightly ahead.
	csrfClockSkew = time.Minute
)

var (
	csrfDomain = []byte("guard/csrf/v1\x00")
	csrfEnc    = base64.RawURLEncoding
	csrfStrict = csrfEnc.Strict()
)

// CSRFConfig configures a CSRF.
type CSRFConfig struct {
	// Now returns the current time. It defaults to time.Now.
	Now func() time.Time
	// Deny writes the response to a request that Handler rejects. err
	// wraps ErrCSRFToken or ErrNoSession. It defaults to a plain 403
	// Forbidden.
	Deny func(w http.ResponseWriter, r *http.Request, err error)
	// Header is the request header Handler reads the token from. It
	// defaults to DefaultCSRFHeader.
	Header string
	// Field is the form field Handler reads the token from when the
	// header is absent. It defaults to DefaultCSRFField.
	Field string
	// Key is the HMAC key, at least MinCSRFKeySize bytes and not all
	// zero. Servers that accept each other's tokens must share it. If it
	// is nil, NewCSRF generates a random key, so tokens are valid only in
	// this process. NewCSRF copies it.
	Key []byte
	// MaxAge is how long a token stays valid, at millisecond precision
	// and at least a millisecond. It defaults to DefaultCSRFMaxAge.
	MaxAge time.Duration
	// MultipartForms also reads the token from multipart/form-data
	// bodies when the header is absent. Parsing one reads the whole body,
	// keeping up to 32 MiB in memory and spilling the rest to temporary
	// files, before the token is checked, so it is off by default:
	// multipart clients, such as scripts uploading files, should send the
	// header instead.
	MultipartForms bool
}

// CSRF issues and verifies tokens that bind state-changing requests to a
// session. It is safe for concurrent use. Its zero value is not usable:
// create one with NewCSRF.
//
// A token is a random nonce, its issue time and an HMAC-SHA-256 of both
// and the session identifier, base64url-encoded. Tokens are stateless and
// signed rather than double-submitted cookies: a double-submit cookie can
// be overwritten by a sibling subdomain or a man in the middle on plain
// HTTP, while a signed token is valid only for the session it was issued
// for. Each call to Token returns a different token, so a token in a
// compressed response does not leak through compression side channels.
type CSRF struct {
	macs      sync.Pool // of *csrfMAC keyed with key
	now       func() time.Time
	deny      func(http.ResponseWriter, *http.Request, error)
	header    string
	field     string
	key       []byte
	maxAge    time.Duration
	multipart bool
}

// NewCSRF returns a CSRF configured by c.
func NewCSRF(c CSRFConfig) (*CSRF, error) {
	key := c.Key
	if key == nil {
		key = make([]byte, 32)
		_, _ = rand.Read(key) // crypto/rand.Read never fails
	} else {
		if len(key) < MinCSRFKeySize {
			return nil, fmt.Errorf("%w: CSRF key shorter than %d bytes", ErrInvalidConfig, MinCSRFKeySize)
		}
		var acc byte
		for _, b := range key {
			acc |= b
		}
		if acc == 0 {
			return nil, fmt.Errorf("%w: all-zero CSRF key", ErrInvalidConfig)
		}
		key = append([]byte(nil), key...)
	}
	if c.MaxAge < 0 || (c.MaxAge > 0 && c.MaxAge < time.Millisecond) {
		return nil, fmt.Errorf("%w: CSRF MaxAge %v is negative or below a millisecond", ErrInvalidConfig, c.MaxAge)
	}
	x := &CSRF{now: c.Now, deny: c.Deny, key: key, header: c.Header, field: c.Field, maxAge: c.MaxAge, multipart: c.MultipartForms}
	if x.now == nil {
		x.now = time.Now
	}
	if x.deny == nil {
		x.deny = deny
	}
	if x.header == "" {
		x.header = DefaultCSRFHeader
	}
	if x.field == "" {
		x.field = DefaultCSRFField
	}
	if x.maxAge == 0 {
		x.maxAge = DefaultCSRFMaxAge
	}
	x.macs.New = func() any { return &csrfMAC{h: hmac.New(sha256.New, key)} }
	return x, nil
}

// Token returns a new token for session, an identifier unique to the
// session that an attacker can neither read nor set, such as the session
// ID or a hash of it. Embed it in forms or send it in the header.
func (x *CSRF) Token(session string) (string, error) {
	if x == nil || x.key == nil {
		return "", ErrUninitialized
	}
	if session == "" {
		return "", ErrNoSession
	}
	var raw [csrfRawLen]byte
	raw[0] = csrfVersion
	binary.BigEndian.PutUint64(raw[1:9], uint64(x.now().UnixMilli()))
	_, _ = rand.Read(raw[9:csrfHeaderLen]) // crypto/rand.Read never fails
	mac := x.sign([csrfHeaderLen]byte(raw[:csrfHeaderLen]), session)
	copy(raw[csrfHeaderLen:], mac[:])
	return csrfEnc.EncodeToString(raw[:]), nil
}

// csrfMAC is a pooled HMAC with buffers that outlive the call, so that
// nothing passed to the hash escapes from the caller's stack.
type csrfMAC struct {
	h       hash.Hash
	session []byte
	header  [csrfHeaderLen]byte
	sum     [sha256.Size]byte
}

// sign returns the MAC of header and session.
func (x *CSRF) sign(header [csrfHeaderLen]byte, session string) [sha256.Size]byte {
	st, _ := x.macs.Get().(*csrfMAC)
	st.header = header
	st.session = append(st.session[:0], session...)
	st.h.Reset()
	st.h.Write(csrfDomain)
	st.h.Write(st.header[:])
	st.h.Write(st.session)
	st.h.Sum(st.sum[:0])
	mac := st.sum
	if cap(st.session) <= 1024 { // do not pool huge buffers
		x.macs.Put(st)
	}
	return mac
}

// Verify checks that token was issued for session within MaxAge.
func (x *CSRF) Verify(session, token string) error {
	if x == nil || x.key == nil {
		return ErrUninitialized
	}
	if session == "" {
		return ErrNoSession
	}
	if len(token) != CSRFTokenLen {
		return ErrCSRFToken
	}
	var src [CSRFTokenLen]byte
	copy(src[:], token)
	var raw [csrfRawLen]byte
	if n, err := csrfStrict.Decode(raw[:], src[:]); err != nil || n != csrfRawLen || raw[0] != csrfVersion {
		return ErrCSRFToken
	}
	mac := x.sign([csrfHeaderLen]byte(raw[:csrfHeaderLen]), session)
	if subtle.ConstantTimeCompare(mac[:], raw[csrfHeaderLen:]) != 1 {
		return ErrCSRFToken
	}
	issued := binary.BigEndian.Uint64(raw[1:9])
	now := x.now().UnixMilli()
	if now < 0 || issued > uint64(now)+uint64(csrfClockSkew.Milliseconds()) ||
		(uint64(now) > issued && uint64(now)-issued > uint64(x.maxAge.Milliseconds())) {
		return fmt.Errorf("%w: expired", ErrCSRFToken)
	}
	return nil
}

// Handler returns h with CSRF tokens required on unsafe requests (other
// than GET, HEAD and OPTIONS). session returns the request's session
// identifier, as passed to Token, or "" if there is none; such unsafe
// requests are rejected too. The token is read from the Header, or else
// from the Field of a URL-encoded form, or of a multipart one with
// MultipartForms. Reading a form parses the body: limit its size with
// http.MaxBytesReader first. A zero CSRF rejects every unsafe request.
//
// To protect a login form, which has no session yet, give the visitor a
// pre-session cookie and use it as the session.
func (x *CSRF) Handler(session func(*http.Request) string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !safeMethod(r.Method) {
			if x == nil || x.key == nil {
				deny(w, r, ErrUninitialized)
				return
			}
			if err := x.Verify(session(r), x.requestToken(r)); err != nil {
				x.deny(w, r, err)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func (x *CSRF) requestToken(r *http.Request) string {
	if t := r.Header.Get(x.header); t != "" {
		return t
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch {
	case mt == "application/x-www-form-urlencoded", mt == "multipart/form-data" && x.multipart:
		return r.PostFormValue(x.field)
	default:
		return ""
	}
}
