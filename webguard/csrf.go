package webguard

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"time"

	"github.com/djylb/guard/internal/conf"
	"github.com/djylb/guard/internal/sign"
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

	errCSRFExpired = fmt.Errorf("%w: expired", ErrCSRFToken)
)

// Defaults of CSRFConfig.
const (
	DefaultCSRFMaxAge = 12 * time.Hour
	DefaultCSRFHeader = "X-CSRF-Token"
	DefaultCSRFField  = "csrf_token"
	// MinCSRFKeySize is the minimum length of CSRFConfig.Key and
	// PreviousKeys.
	MinCSRFKeySize = 16
)

const (
	csrfVersion   = 1
	csrfHeaderLen = 1 + 8 + 16
	csrfRawLen    = csrfHeaderLen + sign.Size
	// CSRFTokenLen is the length of a CSRF token string.
	CSRFTokenLen = (csrfRawLen*8 + 5) / 6
	// csrfClockSkew tolerates tokens issued by servers whose clocks run
	// slightly ahead.
	csrfClockSkew = time.Minute
)

const csrfDomain = "guard/csrf/v1"

var (
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
	// PreviousKeys are keys that still verify but no longer sign, for
	// rotating Key: keep the old key here for one MaxAge.
	PreviousKeys [][]byte
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

// UnmarshalJSON reads a CSRFConfig from a JSON object such as
//
//	{"key": "base64...", "max_age": "12h"}
//
// with the fields header, field, key and previous_keys (standard base64),
// max_age and multipart_forms. Durations are strings in the form of
// time.ParseDuration. Fields that are absent keep their value; unknown
// fields and null values are an error. The key is required unless the
// CSRFConfig already has one; "key": "random" asks for a key generated per
// process. Now and Deny cannot be set from JSON.
func (c *CSRFConfig) UnmarshalJSON(data []byte) error {
	v := struct {
		Header         string        `json:"header"`
		Field          string        `json:"field"`
		Key            conf.Key      `json:"key"`
		PreviousKeys   [][]byte      `json:"previous_keys"`
		MaxAge         conf.Duration `json:"max_age"`
		MultipartForms bool          `json:"multipart_forms"`
	}{c.Header, c.Field, conf.Key{}, c.PreviousKeys, conf.Duration(c.MaxAge), c.MultipartForms}
	if err := conf.Decode(data, &v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	key, err := v.Key.Resolve(c.Key)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	c.Header, c.Field, c.Key, c.PreviousKeys = v.Header, v.Field, key, v.PreviousKeys
	c.MaxAge, c.MultipartForms = time.Duration(v.MaxAge), v.MultipartForms
	return nil
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
	now       func() time.Time
	deny      func(http.ResponseWriter, *http.Request, error)
	signer    *sign.Signer
	header    string
	field     string
	maxAge    time.Duration
	multipart bool
}

// NewCSRF returns a CSRF configured by c.
func NewCSRF(c CSRFConfig) (*CSRF, error) {
	signer, err := sign.New(csrfDomain, c.Key, c.PreviousKeys, MinCSRFKeySize)
	if err != nil {
		return nil, fmt.Errorf("%w: CSRF %w", ErrInvalidConfig, err)
	}
	if c.MaxAge < 0 || (c.MaxAge > 0 && c.MaxAge < time.Millisecond) {
		return nil, fmt.Errorf("%w: CSRF MaxAge %v is negative or below a millisecond", ErrInvalidConfig, c.MaxAge)
	}
	x := &CSRF{now: c.Now, deny: c.Deny, signer: signer, header: c.Header, field: c.Field, maxAge: c.MaxAge, multipart: c.MultipartForms}
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
	return x, nil
}

// Token returns a new token for session, an identifier unique to the
// session that an attacker can neither read nor set, such as the session
// ID or a hash of it. Embed it in forms or send it in the header.
func (x *CSRF) Token(session string) (string, error) {
	if x == nil || x.signer == nil {
		return "", ErrUninitialized
	}
	if session == "" {
		return "", ErrNoSession
	}
	var raw [csrfRawLen]byte
	raw[0] = csrfVersion
	binary.BigEndian.PutUint64(raw[1:9], uint64(x.now().UnixMilli()))
	_, _ = rand.Read(raw[9:csrfHeaderLen]) // crypto/rand.Read never fails
	mac := x.signer.Sign(raw[:csrfHeaderLen], session)
	copy(raw[csrfHeaderLen:], mac[:])
	return csrfEnc.EncodeToString(raw[:]), nil
}

// Verify checks that token was issued for session within MaxAge, with the
// key or one of the previous keys.
func (x *CSRF) Verify(session, token string) error {
	if x == nil || x.signer == nil {
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
	if !x.signer.Verify(raw[csrfHeaderLen:], raw[:csrfHeaderLen], session) {
		return ErrCSRFToken
	}
	issued := binary.BigEndian.Uint64(raw[1:9])
	now := x.now().UnixMilli()
	if now < 0 || issued > uint64(now)+uint64(csrfClockSkew.Milliseconds()) ||
		(uint64(now) > issued && uint64(now)-issued > uint64(x.maxAge.Milliseconds())) {
		return errCSRFExpired
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
			if x == nil || x.signer == nil {
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
