package webguard_test

import (
	"net/http"

	"github.com/djylb/guard/webguard"
)

func Example() {
	csrf, err := webguard.NewCSRF(webguard.CSRFConfig{})
	if err != nil {
		panic(err)
	}
	g, err := webguard.New(webguard.LocalAdmin())
	if err != nil {
		panic(err)
	}
	session := func(r *http.Request) string {
		c, err := r.Cookie("session")
		if err != nil {
			return ""
		}
		return c.Value
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		token, err := csrf.Token(session(r))
		if err != nil {
			http.Error(w, "log in first", http.StatusUnauthorized)
			return
		}
		// Render the form with a hidden csrf_token field set to token.
		_ = token
	})
	mux.HandleFunc("POST /settings", func(http.ResponseWriter, *http.Request) {
		// Reached only by same-origin requests with a valid token.
	})

	srv := &http.Server{Addr: "127.0.0.1:8080", Handler: g.Handler(csrf.Handler(session, mux))}
	_ = srv // srv.ListenAndServe()
}
