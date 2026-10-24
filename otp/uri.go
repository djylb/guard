package otp

import (
	"encoding/base32"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeSecret returns secret in the form authenticator apps expect:
// upper-case base32 without padding.
func EncodeSecret(secret []byte) string {
	return b32.EncodeToString(secret)
}

// DecodeSecret decodes a base32 secret. It accepts lower case and omitted
// padding, as authenticator apps produce, and rejects any other character,
// including spaces and line breaks, as well as non-canonical encodings.
func DecodeSecret(s string) ([]byte, error) {
	if s == "" {
		return nil, ErrInvalidSecret
	}
	// Strip correct padding only: a multiple of 8 characters with a
	// padding length that base32 can produce.
	if strings.HasSuffix(s, "=") {
		data := strings.TrimRight(s, "=")
		switch len(s) - len(data) {
		case 1, 3, 4, 6:
		default:
			return nil, ErrInvalidSecret
		}
		if len(s)%8 != 0 {
			return nil, ErrInvalidSecret
		}
		s = data
	}
	upper := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= '2' && c <= '7':
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		default:
			return nil, ErrInvalidSecret
		}
		upper[i] = c
	}
	out := make([]byte, b32.DecodedLen(len(upper)))
	n, err := b32.Decode(out, upper)
	if err != nil {
		return nil, ErrInvalidSecret
	}
	out = out[:n]
	// The decoder ignores unused trailing bits; reject encodings that
	// set them, so that each secret has a single spelling.
	if b32.EncodeToString(out) != string(upper) {
		return nil, ErrInvalidSecret
	}
	return out, nil
}

// URI returns the otpauth:// URI of k in the Key Uri Format that
// authenticator apps import, usually from a QR code. Parameters equal to
// their defaults are omitted, except the secret, the issuer and, for HOTP,
// the counter.
func (k *Key) URI() (string, error) {
	digits, period, err := k.params()
	if err != nil {
		return "", err
	}
	switch k.Kind {
	case TOTP, HOTP:
	default:
		return "", fmt.Errorf("%w: unknown %v", ErrInvalidKey, k.Kind)
	}
	var b strings.Builder
	b.WriteString("otpauth://")
	b.WriteString(k.Kind.String())
	b.WriteByte('/')
	// Without an issuer, an escaped colon in the account would read as
	// the separator; an empty issuer before a literal one avoids that.
	account := escapeLabel(k.Account)
	if k.Issuer != "" || strings.Contains(k.Account, ":") {
		b.WriteString(escapeLabel(k.Issuer))
		b.WriteByte(':')
	}
	b.WriteString(account)
	b.WriteString("?secret=")
	b.WriteString(EncodeSecret(k.Secret))
	if k.Issuer != "" {
		b.WriteString("&issuer=")
		b.WriteString(escapeQuery(k.Issuer))
	}
	if k.Algorithm != SHA1 {
		b.WriteString("&algorithm=")
		b.WriteString(k.Algorithm.String())
	}
	if digits != DefaultDigits {
		b.WriteString("&digits=")
		b.WriteString(strconv.Itoa(digits))
	}
	switch k.Kind {
	case TOTP:
		if period != uint64(DefaultPeriod/time.Second) {
			b.WriteString("&period=")
			b.WriteString(strconv.FormatUint(period, 10))
		}
	case HOTP:
		b.WriteString("&counter=")
		b.WriteString(strconv.FormatUint(k.Counter, 10))
	}
	return b.String(), nil
}

// escapeLabel escapes a label part, including the colon that separates
// the issuer from the account.
func escapeLabel(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), ":", "%3A")
}

// escapeQuery escapes a query value with %20 for spaces, which every app
// reads, rather than '+', which some show literally.
func escapeQuery(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

// ParseURI parses an otpauth:// URI. It requires the secret, and the
// counter for HOTP; it rejects repeated parameters, unknown algorithms,
// out-of-range digits and periods, and an issuer parameter that differs
// from the issuer in the label. Unknown parameters, such as image, are
// ignored. The returned Key has Skew 0.
func ParseURI(uri string) (*Key, error) {
	// The URI is split by hand: a label may hold characters that
	// net/url would re-escape, losing which colon was literal.
	const scheme = "otpauth://"
	if len(uri) < len(scheme) || !strings.EqualFold(uri[:len(scheme)], scheme) || strings.ContainsAny(uri, "#") {
		return nil, ErrInvalidURI
	}
	rest, rawQuery, _ := strings.Cut(uri[len(scheme):], "?")
	typ, label, ok := strings.Cut(rest, "/")
	if !ok {
		return nil, fmt.Errorf("%w: no label", ErrInvalidURI)
	}
	k := &Key{}
	switch strings.ToLower(typ) {
	case "totp":
		k.Kind = TOTP
	case "hotp":
		k.Kind = HOTP
	default:
		return nil, fmt.Errorf("%w: type %q", ErrInvalidURI, typ)
	}
	if strings.Contains(label, "/") {
		return nil, fmt.Errorf("%w: label contains '/'", ErrInvalidURI)
	}
	// A literal colon separates the issuer from the account, and an
	// escaped one does only if there is no literal one.
	issuer, account, hasIssuer := strings.Cut(label, ":")
	if !hasIssuer {
		if i := escapedColon(label); i >= 0 {
			issuer, account, hasIssuer = label[:i], label[i+3:], true
		} else {
			issuer, account = "", label
		}
	}
	var err error
	if k.Issuer, err = url.PathUnescape(issuer); err != nil {
		return nil, ErrInvalidURI
	}
	if k.Account, err = url.PathUnescape(account); err != nil {
		return nil, ErrInvalidURI
	}
	k.Account = strings.TrimLeft(k.Account, " ")
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return nil, ErrInvalidURI
	}
	get := func(name string) (string, bool, error) {
		v := q[name]
		switch len(v) {
		case 0:
			return "", false, nil
		case 1:
			return v[0], true, nil
		default:
			return "", false, fmt.Errorf("%w: repeated %s", ErrInvalidURI, name)
		}
	}
	secret, ok, err := get("secret")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: no secret", ErrInvalidURI)
	}
	if k.Secret, err = DecodeSecret(secret); err != nil {
		return nil, err
	}
	if v, ok, err := get("issuer"); err != nil {
		return nil, err
	} else if ok {
		if hasIssuer && v != k.Issuer {
			return nil, fmt.Errorf("%w: issuer %q differs from label issuer %q", ErrInvalidURI, v, k.Issuer)
		}
		k.Issuer = v
	}
	if v, ok, err := get("algorithm"); err != nil {
		return nil, err
	} else if ok {
		switch strings.ToUpper(v) {
		case "SHA1":
			k.Algorithm = SHA1
		case "SHA256":
			k.Algorithm = SHA256
		case "SHA512":
			k.Algorithm = SHA512
		default:
			return nil, fmt.Errorf("%w: algorithm %q", ErrInvalidURI, v)
		}
	}
	if v, ok, err := get("digits"); err != nil {
		return nil, err
	} else if ok {
		n, ok := parseDecimal(v)
		if !ok || n < MinDigits || n > MaxDigits {
			return nil, fmt.Errorf("%w: digits %q", ErrInvalidURI, v)
		}
		k.Digits = int(n)
	}
	if v, ok, err := get("period"); err != nil {
		return nil, err
	} else if ok {
		n, ok := parseDecimal(v)
		if !ok || n == 0 || n > uint64(1<<63-1)/uint64(time.Second) {
			return nil, fmt.Errorf("%w: period %q", ErrInvalidURI, v)
		}
		k.Period = time.Duration(n) * time.Second
	}
	v, ok, err := get("counter")
	if err != nil {
		return nil, err
	}
	switch k.Kind {
	case HOTP:
		n, valid := parseDecimal(v)
		if !ok || !valid {
			return nil, fmt.Errorf("%w: counter %q", ErrInvalidURI, v)
		}
		k.Counter = n
	case TOTP:
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return k, nil
}

// parseDecimal parses a non-empty string of ASCII digits, without sign or
// separators.
func parseDecimal(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		d := uint64(c - '0')
		if n > (1<<64-1-d)/10 {
			return 0, false
		}
		n = n*10 + d
	}
	return n, true
}

// escapedColon returns the index of the first "%3A" or "%3a" in s, or -1.
func escapedColon(s string) int {
	for i := 0; i+2 < len(s); i++ {
		if s[i] == '%' && s[i+1] == '3' && (s[i+2] == 'A' || s[i+2] == 'a') {
			return i
		}
	}
	return -1
}
