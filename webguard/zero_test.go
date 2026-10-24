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
	var g Guard
	var nilG *Guard
	for _, h := range []http.Handler{g.Handler(okHandler), nilG.Handler(okHandler), g.Handler(nil)} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://localhost/", nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("zero Guard: %d", rec.Code)
		}
	}
	if err := g.Check(httptest.NewRequest(http.MethodGet, "http://localhost/", nil)); !errors.Is(err, ErrUninitialized) {
		t.Error(err)
	}
	var x CSRF
	var nilX *CSRF
	for _, h := range []http.Handler{x.Handler(func(*http.Request) string { return "s" }, okHandler), nilX.Handler(nil, okHandler)} {
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
	if err := x.Verify("s", tok); err != nil {
		t.Fatalf("within MaxAge: %v", err)
	}
	clk.Advance(401 * time.Millisecond)
	if err := x.Verify("s", tok); !errors.Is(err, ErrCSRFToken) {
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
