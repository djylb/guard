package webguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/djylb/guard/internal/race"
)

type fakeClock struct {
	ns atomic.Int64
}

func newFakeClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	return c
}

func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

var testKey = []byte("0123456789abcdef0123456789abcdef")

func mustCSRF(t testing.TB, c CSRFConfig) *CSRF {
	t.Helper()
	x, err := NewCSRF(c)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func newCSRF(t testing.TB, clk *fakeClock) *CSRF {
	t.Helper()
	x, err := NewCSRF(CSRFConfig{Now: clk.Now, Key: testKey, MaxAge: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return x
}

func TestCSRFToken(t *testing.T) {
	clk := newFakeClock()
	x := newCSRF(t, clk)
	tok, err := x.Token("session-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != CSRFTokenLen {
		t.Fatalf("length %d", len(tok))
	}
	tok2, _ := x.Token("session-a")
	if tok == tok2 {
		t.Fatal("tokens repeat")
	}
	if err := x.Verify(tok, "session-a"); err != nil {
		t.Fatal(err)
	}
	if err := x.Verify(tok, "session-a"); err != nil {
		t.Fatal("a token is valid for its whole lifetime")
	}
	if err := x.Verify(tok, "session-b"); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("other session: %v", err)
	}
	if err := x.Verify(tok, ""); !errors.Is(err, ErrNoSession) {
		t.Fatal(err)
	}
	if _, err := x.Token(""); !errors.Is(err, ErrNoSession) {
		t.Fatal(err)
	}
	other := mustCSRF(t, CSRFConfig{Now: clk.Now})
	if err := other.Verify(tok, "session-a"); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("other key: %v", err)
	}
	clk.Advance(time.Hour)
	if err := x.Verify(tok, "session-a"); err != nil {
		t.Fatalf("at MaxAge: %v", err)
	}
	clk.Advance(time.Second)
	if err := x.Verify(tok, "session-a"); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("after MaxAge: %v", err)
	}
	// A token from a clock far ahead is rejected.
	clk.Advance(-time.Hour - time.Second - 30*time.Second)
	if err := x.Verify(tok, "session-a"); err != nil {
		t.Fatalf("within skew: %v", err)
	}
	clk.Advance(-time.Hour)
	if err := x.Verify(tok, "session-a"); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("issued in the future: %v", err)
	}
}

func TestCSRFTamper(t *testing.T) {
	clk := newFakeClock()
	x := newCSRF(t, clk)
	tok, _ := x.Token("s")
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		for _, bit := range []byte{0x01, 0x80} {
			mod := append([]byte(nil), raw...)
			mod[i] ^= bit
			if err := x.Verify(base64.RawURLEncoding.EncodeToString(mod), "s"); !errors.Is(err, ErrCSRFToken) {
				t.Fatalf("byte %d bit %#x flipped: %v", i, bit, err)
			}
		}
	}
	for _, bad := range []string{"", tok[1:], tok + "A", strings.Repeat("*", CSRFTokenLen), tamper(tok)} {
		if bad == tok {
			continue
		}
		if err := x.Verify(bad, "s"); !errors.Is(err, ErrCSRFToken) {
			t.Errorf("Verify(%q) = %v", bad, err)
		}
	}
}

func TestCSRFConfig(t *testing.T) {
	for _, c := range []CSRFConfig{
		{Key: []byte("short")},
		{Key: make([]byte, 32)},
		{Key: testKey, MaxAge: -1},
	} {
		if _, err := NewCSRF(c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("NewCSRF(%+v) = %v", c, err)
		}
	}
	var x CSRF
	if _, err := x.Token("s"); !errors.Is(err, ErrUninitialized) {
		t.Error(err)
	}
	if err := x.Verify("t", "s"); !errors.Is(err, ErrUninitialized) {
		t.Error(err)
	}
	key := append([]byte(nil), testKey...)
	y := mustCSRF(t, CSRFConfig{Key: key})
	tok, _ := y.Token("s")
	key[0] ^= 1
	if err := y.Verify(tok, "s"); err != nil {
		t.Fatal("NewCSRF did not copy the key")
	}
}

func TestCSRFHandler(t *testing.T) {
	clk := newFakeClock()
	x := newCSRF(t, clk)
	session := func(r *http.Request) string { return r.Header.Get("X-Session") }
	h := x.Handler(session, okHandler)
	tok, _ := x.Token("s1")
	form := url.Values{DefaultCSRFField: {tok}}.Encode()
	tests := []struct {
		name, method, session, header, body, ctype string
		want                                       int
	}{
		{"GET", http.MethodGet, "", "", "", "", http.StatusNoContent},
		{"header", http.MethodPost, "s1", tok, "", "", http.StatusNoContent},
		{"form", http.MethodPost, "s1", "", form, "application/x-www-form-urlencoded", http.StatusNoContent},
		{"form charset", http.MethodPost, "s1", "", form, "application/x-www-form-urlencoded; charset=utf-8", http.StatusNoContent},
		{"form ignored for JSON", http.MethodPost, "s1", "", form, "application/json", http.StatusForbidden},
		{"no token", http.MethodPost, "s1", "", "", "", http.StatusForbidden},
		{"no session", http.MethodPost, "", tok, "", "", http.StatusForbidden},
		{"other session", http.MethodDelete, "s2", tok, "", "", http.StatusForbidden},
	}
	for _, tt := range tests {
		r := httptest.NewRequest(tt.method, "http://localhost/x", strings.NewReader(tt.body))
		if tt.session != "" {
			r.Header.Set("X-Session", tt.session)
		}
		if tt.header != "" {
			r.Header.Set(DefaultCSRFHeader, tt.header)
		}
		if tt.ctype != "" {
			r.Header.Set("Content-Type", tt.ctype)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != tt.want {
			t.Errorf("%s: %d, want %d", tt.name, rec.Code, tt.want)
		}
	}
}

func FuzzCSRFVerify(f *testing.F) {
	clk := newFakeClock()
	x := newCSRF(f, clk)
	tok, _ := x.Token("s")
	f.Add("s", tok)
	f.Add("", "")
	f.Add("s", strings.Repeat("A", CSRFTokenLen))
	f.Fuzz(func(t *testing.T, session, token string) {
		err := x.Verify(token, session)
		if err == nil && !authentic(session, token) {
			t.Fatalf("Verify(%q, %q) accepted", token, session)
		}
	})
}

func BenchmarkCSRFVerify(b *testing.B) {
	x := mustCSRF(b, CSRFConfig{Key: testKey})
	tok, _ := x.Token("session")
	b.ReportAllocs()
	for b.Loop() {
		if err := x.Verify(tok, "session"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCSRFToken(b *testing.B) {
	x := mustCSRF(b, CSRFConfig{Key: testKey})
	b.ReportAllocs()
	for b.Loop() {
		_, _ = x.Token("session")
	}
}

// authentic recomputes a token's MAC independently of the signer.
func authentic(session, token string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != csrfRawLen {
		return false
	}
	m := hmac.New(sha256.New, testKey)
	m.Write([]byte("guard/csrf/v1\x00"))
	m.Write(raw[:csrfHeaderLen])
	m.Write(binary.AppendUvarint(nil, uint64(len(session))))
	m.Write([]byte(session))
	return hmac.Equal(m.Sum(nil), raw[csrfHeaderLen:])
}

func TestCSRFKeyRotation(t *testing.T) {
	newKey := []byte("fedcba9876543210fedcba9876543210")
	old := mustCSRF(t, CSRFConfig{Key: testKey})
	rotated := mustCSRF(t, CSRFConfig{Key: newKey, PreviousKeys: [][]byte{testKey}})
	token, _ := old.Token("s")
	if err := rotated.Verify(token, "s"); err != nil {
		t.Fatalf("previous key: %v", err)
	}
	if err := mustCSRF(t, CSRFConfig{Key: newKey}).Verify(token, "s"); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("retired key: %v", err)
	}
	token, _ = rotated.Token("s")
	if err := old.Verify(token, "s"); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("rotated CSRF still signs with the old key: %v", err)
	}
	if err := rotated.Verify(token, "s"); err != nil {
		t.Fatalf("own token with previous keys: %v", err)
	}
	if _, err := NewCSRF(CSRFConfig{PreviousKeys: [][]byte{testKey}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal(err)
	}
}

// TestCSRFAllocs checks that Verify does not allocate, also when it
// rejects an expired or forged token.
func TestCSRFAllocs(t *testing.T) {
	if race.Enabled() {
		t.Skip("sync.Pool drops items in race builds")
	}
	clk := newFakeClock()
	x := mustCSRF(t, CSRFConfig{Now: clk.Now, Key: testKey, MaxAge: time.Minute})
	old, _ := x.Token("s")
	clk.Advance(2 * time.Minute)
	fresh, _ := x.Token("s")
	for token, want := range map[string]error{fresh: nil, old: ErrCSRFToken, tamper(fresh): ErrCSRFToken} {
		if err := x.Verify(token, "s"); !errors.Is(err, want) {
			t.Fatalf("Verify = %v, want %v", err, want)
		}
		if n := testing.AllocsPerRun(100, func() { _ = x.Verify(token, "s") }); n != 0 {
			t.Errorf("Verify (want %v) allocates %v times", want, n)
		}
	}
}

// TestCSRFHandlerAllocs checks that the handler path, accepting a header
// token or rejecting a request without one, does not allocate.
func TestCSRFHandlerAllocs(t *testing.T) {
	if race.Enabled() {
		t.Skip("the race detector allocates")
	}
	clk := newFakeClock()
	x := newCSRF(t, clk)
	h := x.Handler(func(*http.Request) string { return "s1" }, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	tok, _ := x.Token("s1")
	w := httptest.NewRecorder()
	ok := httptest.NewRequest(http.MethodPost, "http://localhost/x", nil)
	ok.Header.Set("x-csrf-token", tok)
	missing := httptest.NewRequest(http.MethodPost, "http://localhost/x", nil)
	missing.Header.Set("Content-Type", "application/json; charset=utf-8")
	quiet := mustCSRF(t, CSRFConfig{Now: clk.Now, Key: testKey, Deny: func(http.ResponseWriter, *http.Request, error) {}})
	hq := quiet.Handler(func(*http.Request) string { return "s1" }, h)
	for name, run := range map[string]func(){
		"accept": func() { h.ServeHTTP(w, ok) },
		"reject": func() { hq.ServeHTTP(w, missing) },
	} {
		if n := testing.AllocsPerRun(100, run); n != 0 {
			t.Errorf("%s allocates %v times", name, n)
		}
	}
}

func TestCSRFConfigChecks(t *testing.T) {
	for _, c := range []CSRFConfig{
		{Key: testKey, Header: "X CSRF"},
		{Key: testKey, Header: "X-Token:"},
		{Key: testKey, Skew: -time.Second},
	} {
		if _, err := NewCSRF(c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("NewCSRF(%+v) = %v", c, err)
		}
	}
	// A header name in any case is read in canonical form.
	x := mustCSRF(t, CSRFConfig{Key: testKey, Header: "x-my-TOKEN"})
	tok, _ := x.Token("s")
	r := httptest.NewRequest(http.MethodPost, "http://localhost/x", nil)
	r.Header.Set("X-My-Token", tok)
	rec := httptest.NewRecorder()
	x.Handler(func(*http.Request) string { return "s" }, okHandler).ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("header token rejected: %d", rec.Code)
	}
}

func TestCSRFSkew(t *testing.T) {
	clk := newFakeClock()
	ahead := newFakeClock()
	ahead.Advance(10 * time.Second)
	issuer := mustCSRF(t, CSRFConfig{Now: ahead.Now, Key: testKey})
	tok, _ := issuer.Token("s")
	strict := mustCSRF(t, CSRFConfig{Now: clk.Now, Key: testKey, Skew: 5 * time.Second})
	if err := strict.Verify(tok, "s"); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("token from 10s ahead with 5s skew: %v", err)
	}
	if err := mustCSRF(t, CSRFConfig{Now: clk.Now, Key: testKey}).Verify(tok, "s"); err != nil {
		t.Fatalf("token within the default skew: %v", err)
	}
}

// tamper returns tok with its last character replaced by a different one.
func tamper(tok string) string {
	c := byte('A')
	if tok[len(tok)-1] == c {
		c = 'B'
	}
	return tok[:len(tok)-1] + string(c)
}

// TestTamper is a regression test: the tampered token differs from the
// original, also when that ends in the replacement character.
func TestTamper(t *testing.T) {
	for _, tok := range []string{"xyzA", "xyzB", "xyz_"} {
		if tamper(tok) == tok {
			t.Errorf("tamper(%q) is unchanged", tok)
		}
	}
}
