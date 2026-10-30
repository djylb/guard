package webguard

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"
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
	DefaultCSRFSkew   = time.Minute
	DefaultCSRFHeader = "X-CSRF-Token"
	DefaultCSRFField  = "csrf_token"
	// MinCSRFKeySize is the minimum length of CSRFConfig.Key and
	// PreviousKeys.
	MinCSRFKeySize = 16
)

const (
	csrfVersion   = 1
	csrfHeaderLen = 1 + 8 + sign.NonceSize
	csrfRawLen    = csrfHeaderLen + sign.Size
	// CSRFTokenLen is the length of a CSRF token string.
	CSRFTokenLen = (csrfRawLen*8 + 5) / 6
)

const csrfDomain = "guard/csrf/v1"

// CSRFConfig configures a CSRF.
type CSRFConfig struct {
	// Now returns the current time. It defaults to time.Now.
	Now func() time.Time
	// Deny writes the response to a request that Handler rejects. err
	// wraps ErrCSRFToken or ErrNoSession. It defaults to a plain 403
	// Forbidden.
	Deny func(w http.ResponseWriter, r *http.Request, err error)
	// Header is the request header Handler reads the token from, a
	// valid header name compared case-insensitively. It defaults to
	// DefaultCSRFHeader.
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
	// Skew is how far ahead of this server's clock the clock of a server
	// that issued a token may run. It defaults to DefaultCSRFSkew and
	// must not be negative.
	Skew time.Duration
	// MultipartForms also reads the token from multipart/form-data
	// bodies when the header is absent. Parsing one reads the whole body,
	// keeping up to 32 MiB in memory and spilling the rest to temporary
	// files, before the token is checked, so it is off by default:
	// multipart clients, such as scripts uploading files, should send the
	// header instead.
	MultipartForms bool
}

// csrfJSON is the JSON form of a CSRFConfig.
type csrfJSON struct {
	Header         string        `json:"header"`
	Field          string        `json:"field"`
	Key            conf.Key      `json:"key,omitzero"`
	PreviousKeys   [][]byte      `json:"previous_keys,omitempty"`
	MaxAge         conf.Duration `json:"max_age"`
	Skew           conf.Duration `json:"skew"`
	MultipartForms bool          `json:"multipart_forms"`
}

// json returns c in JSON form, with the key absent.
//
//goland:noinspection GoMixedReceiverTypes
func (c *CSRFConfig) json() csrfJSON {
	return csrfJSON{c.Header, c.Field, conf.Key{}, c.PreviousKeys, conf.Duration(c.MaxAge), conf.Duration(c.Skew), c.MultipartForms}
}

// UnmarshalJSON reads a CSRFConfig from a JSON object such as
//
//	{"key": "base64...", "max_age": "12h"}
//
// with the fields header, field, key and previous_keys (standard base64),
// max_age, skew and multipart_forms. Durations are strings in the form of
// time.ParseDuration. Fields that are absent keep their value; unknown,
// repeated and null fields are an error, and names must match exactly.
// The key is required unless the CSRFConfig already has one; "key":
// "random" asks for a key generated per process. Now and Deny cannot be
// set from JSON.
//
//goland:noinspection GoMixedReceiverTypes
func (c *CSRFConfig) UnmarshalJSON(data []byte) error {
	v := c.json()
	if err := conf.Decode(data, &v); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	key, err := v.Key.Resolve(c.Key)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	c.Header, c.Field, c.Key, c.PreviousKeys = v.Header, v.Field, key, v.PreviousKeys
	c.MaxAge, c.Skew, c.MultipartForms = time.Duration(v.MaxAge), time.Duration(v.Skew), v.MultipartForms
	return nil
}

// MarshalJSON writes c in the form UnmarshalJSON reads, for logging the
// effective configuration. It writes no secret: the key is "random" if
// it is nil and left out otherwise, and PreviousKeys, Now and Deny are
// left out.
//
//goland:noinspection GoMixedReceiverTypes
func (c CSRFConfig) MarshalJSON() ([]byte, error) {
	v := c.json()
	v.Key, v.PreviousKeys = conf.Redacted(c.Key), nil
	return json.Marshal(v)
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
	header    string // canonical
	field     string
	maxAge    time.Duration
	skew      time.Duration
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
	if c.Skew < 0 {
		return nil, fmt.Errorf("%w: CSRF Skew %v is negative", ErrInvalidConfig, c.Skew)
	}
	x := &CSRF{now: c.Now, deny: c.Deny, signer: signer, header: c.Header, field: c.Field, maxAge: c.MaxAge, skew: c.Skew, multipart: c.MultipartForms}
	if x.now == nil {
		x.now = time.Now
	}
	if x.deny == nil {
		x.deny = deny
	}
	if x.header == "" {
		x.header = DefaultCSRFHeader
	}
	if !validToken(x.header) {
		return nil, fmt.Errorf("%w: CSRF header %q is not a header name", ErrInvalidConfig, x.header)
	}
	// Stored in canonical form, so that reading it needs no conversion.
	x.header = textproto.CanonicalMIMEHeaderKey(x.header)
	if x.skew == 0 {
		x.skew = DefaultCSRFSkew
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
	return x.signer.Seal(raw[:], session), nil
}

// Verify checks that token was issued for session within MaxAge, with the
// key or one of the previous keys. It does not allocate. Unlike a
// challenge, a token stays valid for its whole MaxAge and may be used
// many times: it binds requests to a session, it does not count them.
func (x *CSRF) Verify(token, session string) error {
	if x == nil || x.signer == nil {
		return ErrUninitialized
	}
	if session == "" {
		return ErrNoSession
	}
	var raw [csrfRawLen]byte
	if !sign.Open(raw[:], token) || raw[0] != csrfVersion {
		return ErrCSRFToken
	}
	if !x.signer.Check(raw[:], session) {
		return ErrCSRFToken
	}
	issued := binary.BigEndian.Uint64(raw[1:9])
	now := x.now().UnixMilli()
	if now < 0 || issued > uint64(now)+uint64(x.skew.Milliseconds()) ||
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
// Checking a token from the header does not allocate, nor does rejecting
// a request without one; parsing a form body allocates inside net/http.
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
			if err := x.Verify(x.requestToken(r), session(r)); err != nil {
				x.deny(w, r, err)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func (x *CSRF) requestToken(r *http.Request) string {
	if v := r.Header[x.header]; len(v) > 0 && v[0] != "" {
		return v[0]
	}
	var ct string
	if v := r.Header["Content-Type"]; len(v) > 0 {
		ct = v[0]
	}
	// Compare the media type by hand, as net/http does to pick its form
	// parser, rather than with mime.ParseMediaType, which allocates.
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	switch {
	case strings.EqualFold(ct, "application/x-www-form-urlencoded"),
		x.multipart && strings.EqualFold(ct, "multipart/form-data"):
		return r.PostFormValue(x.field)
	default:
		return ""
	}
}
