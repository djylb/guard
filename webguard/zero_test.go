package webguard

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestZeroValues(t *testing.T) {
	// A nil and a zero Guard and CSRF all fail closed.
	for _, g := range []*Guard{nil, new(Guard)} {
		for _, h := range []http.Handler{g.Handler(okHandler), g.Handler(nil)} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("zero Guard: %d", rec.Code)
			}
		}
		r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
		if err := g.Check(r); !errors.Is(err, ErrUninitialized) {
			t.Error(err)
		}
		if _, err := g.ClientAddr(r); !errors.Is(err, ErrUninitialized) {
			t.Error(err)
		}
	}
	for _, x := range []*CSRF{nil, new(CSRF)} {
		h := x.Handler(func(*http.Request) string { return "s" }, okHandler)
		if _, err := x.Token("s"); !errors.Is(err, ErrUninitialized) {
			t.Error(err)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://localhost/", nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("zero CSRF: %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
		if rec.Code != http.StatusNoContent {
			t.Errorf("zero CSRF, GET: %d", rec.Code)
		}
	}
}

func TestCSRFSubSecondMaxAge(t *testing.T) {
	clk := newFakeClock()
	clk.Advance(900 * time.Millisecond)
	x := mustCSRF(t, CSRFConfig{Now: clk.Now, MaxAge: 1500 * time.Millisecond})
	tok, _ := x.Token("s")
	clk.Advance(1100 * time.Millisecond)
	if err := x.Verify(tok, "s"); err != nil {
		t.Fatalf("within MaxAge: %v", err)
	}
	clk.Advance(401 * time.Millisecond)
	if err := x.Verify(tok, "s"); !errors.Is(err, ErrCSRFToken) {
		t.Fatalf("after MaxAge: %v", err)
	}
	if _, err := NewCSRF(CSRFConfig{MaxAge: time.Microsecond}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal(err)
	}
}

func TestCSRFMultipart(t *testing.T) {
	clk := newFakeClock()
	session := func(*http.Request) string { return "s" }
	for _, opt := range []bool{false, true} {
		x := mustCSRF(t, CSRFConfig{Now: clk.Now, Key: testKey, MultipartForms: opt})
		tok, _ := x.Token("s")
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		_ = mw.WriteField(DefaultCSRFField, tok)
		_ = mw.Close()
		r := httptest.NewRequest(http.MethodPost, "http://localhost/", &body)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		rec := httptest.NewRecorder()
		x.Handler(session, okHandler).ServeHTTP(rec, r)
		want := http.StatusForbidden
		if opt {
			want = http.StatusNoContent
		}
		if rec.Code != want {
			t.Errorf("MultipartForms %v: %d, want %d", opt, rec.Code, want)
		}
		if !opt && r.MultipartForm != nil {
			t.Error("multipart body parsed although MultipartForms is off")
		}
	}
}
