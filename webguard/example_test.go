package webguard_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/djylb/guard/webguard"
)

func sessionID(r *http.Request) string {
	c, err := r.Cookie("__Host-session")
	if err != nil {
		return ""
	}
	return c.Value
}

func Example() {
	csrf, err := webguard.NewCSRF(webguard.CSRFConfig{})
	if err != nil {
		panic(err)
	}
	g, err := webguard.New(webguard.LocalAdmin())
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		token, err := csrf.Token(sessionID(r))
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

	srv := &http.Server{Addr: "127.0.0.1:8080", Handler: g.Handler(csrf.Handler(sessionID, mux))}
	_ = srv // srv.ListenAndServe()
}

// An admin page behind a reverse proxy, open to one network.
func ExampleGuard_ClientAddr() {
	g, err := webguard.New(webguard.Config{
		Hosts:           []string{"admin.example.com"},
		TrustedProxies:  []string{"10.0.0.2", "10.0.0.3"},
		Peers:           []string{"192.0.2.0/24"},
		RequireOrigin:   true,
		SecurityHeaders: true,
	})
	if err != nil {
		panic(err)
	}
	r := httptest.NewRequest(http.MethodGet, "https://admin.example.com/", nil)
	r.RemoteAddr = "10.0.0.2:41000" // the proxy
	r.Header.Set("X-Forwarded-For", "203.0.113.50, 192.0.2.17")
	addr, err := g.ClientAddr(r) // key per-client limits on it
	fmt.Println(addr, err, g.Check(r))
	// Output: 192.0.2.17 <nil> <nil>
}
