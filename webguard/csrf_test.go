package webguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	if err := x.Verify("session-a", tok); err != nil {
		t.Fatal(err)
	}
	if err := x.Verify("session-a", tok); err != nil {
		t.Fatal("a token is valid for its whole lifetime")
	}
	if err := x.Verify("session-b", tok); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("other session: %v", err)
	}
	if err := x.Verify("", tok); !errors.Is(err, ErrNoSession) {
		t.Fatal(err)
	}
	if _, err := x.Token(""); !errors.Is(err, ErrNoSession) {
		t.Fatal(err)
	}
	other := mustCSRF(t, CSRFConfig{Now: clk.Now})
	if err := other.Verify("session-a", tok); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("other key: %v", err)
	}
	clk.Advance(time.Hour)
	if err := x.Verify("session-a", tok); err != nil {
		t.Fatalf("at MaxAge: %v", err)
	}
	clk.Advance(time.Second)
	if err := x.Verify("session-a", tok); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("after MaxAge: %v", err)
	}
	// A token from a clock far ahead is rejected.
	clk.Advance(-time.Hour - time.Second - 30*time.Second)
	if err := x.Verify("session-a", tok); err != nil {
		t.Fatalf("within skew: %v", err)
	}
	clk.Advance(-time.Hour)
	if err := x.Verify("session-a", tok); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("issued in the future: %v", err)
	}
}

func TestCSRFTamper(t *testing.T) {
	clk := newFakeClock()
	x := newCSRF(t, clk)
	tok, _ := x.Token("s")
	raw, err := csrfEnc.DecodeString(tok)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		for _, bit := range []byte{0x01, 0x80} {
			mod := append([]byte(nil), raw...)
			mod[i] ^= bit
			if err := x.Verify("s", csrfEnc.EncodeToString(mod)); !errors.Is(err, ErrCSRFToken) {
				t.Fatalf("byte %d bit %#x flipped: %v", i, bit, err)
			}
		}
	}
	for _, bad := range []string{"", tok[1:], tok + "A", strings.Repeat("*", CSRFTokenLen), tok[:CSRFTokenLen-1] + "B"} {
		if bad == tok {
			continue
		}
		if err := x.Verify("s", bad); !errors.Is(err, ErrCSRFToken) {
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
	if err := x.Verify("s", "t"); !errors.Is(err, ErrUninitialized) {
		t.Error(err)
	}
	key := append([]byte(nil), testKey...)
	y := mustCSRF(t, CSRFConfig{Key: key})
	tok, _ := y.Token("s")
	key[0] ^= 1
	if err := y.Verify("s", tok); err != nil {
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
		err := x.Verify(session, token)
		if err == nil && !authentic(session, token) {
			t.Fatalf("Verify(%q, %q) accepted", session, token)
		}
	})
}

func BenchmarkCSRFVerify(b *testing.B) {
	x := mustCSRF(b, CSRFConfig{Key: testKey})
	tok, _ := x.Token("session")
	b.ReportAllocs()
	for b.Loop() {
		if err := x.Verify("session", tok); err != nil {
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
	raw, err := csrfEnc.DecodeString(token)
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
	if err := rotated.Verify("s", token); err != nil {
		t.Fatalf("previous key: %v", err)
	}
	if err := mustCSRF(t, CSRFConfig{Key: newKey}).Verify("s", token); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("retired key: %v", err)
	}
	token, _ = rotated.Token("s")
	if err := old.Verify("s", token); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("rotated CSRF still signs with the old key: %v", err)
	}
	if err := rotated.Verify("s", token); err != nil {
		t.Fatalf("own token with previous keys: %v", err)
	}
	if _, err := NewCSRF(CSRFConfig{PreviousKeys: [][]byte{testKey}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal(err)
	}
}

// TestCSRFAllocs checks that Verify does not allocate, also when it
// rejects an expired or forged token.
func TestCSRFAllocs(t *testing.T) {
	if raceEnabled {
		t.Skip("sync.Pool drops items in race builds")
	}
	clk := newFakeClock()
	x := mustCSRF(t, CSRFConfig{Now: clk.Now, Key: testKey, MaxAge: time.Minute})
	old, _ := x.Token("s")
	clk.Advance(2 * time.Minute)
	fresh, _ := x.Token("s")
	for token, want := range map[string]error{fresh: nil, old: ErrCSRFToken, fresh[:CSRFTokenLen-1] + "A": ErrCSRFToken} {
		if err := x.Verify("s", token); !errors.Is(err, want) && err != want {
			t.Fatalf("Verify = %v, want %v", err, want)
		}
		if n := testing.AllocsPerRun(100, func() { _ = x.Verify("s", token) }); n != 0 {
			t.Errorf("Verify (want %v) allocates %v times", want, n)
		}
	}
}
