package main

import (
	"errors"
	"flag"
	"log"
	"net/http"
)

var (
	CookieName = "X-KFIRS-Auth"
)

func authHandler(w http.ResponseWriter, r *http.Request) {
	//origMethod := r.Header.Get("X-Forwarded-Method")
	//origProto := r.Header.Get("X-Forwarded-Proto")
	//origHost := r.Header.Get("X-Forwarded-Host")
	//origURI := r.Header.Get("X-Forwarded-Uri")
	//origSourceIP := r.Header.Get("X-Forwarded-For")

	if auth, err := r.Cookie(CookieName); err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			log.Printf("Cookie '%s' not found (user not authenticated) - redirecting to Google OAuth2 page", CookieName)
			w.WriteHeader(200)
		} else {
			log.Printf("Failed to read cookie '%s': %v", CookieName, err)
			w.WriteHeader(500)
		}
	} else {
		// TODO: validate the cookie value (probably will need a secret for hashing)
		log.Printf("Cookie '%s' found (user authenticated) - redirecting to original URL; auth info: %s", CookieName, auth.Value)
		w.WriteHeader(200)
	}
}

func validateHandler(_ http.ResponseWriter, _ *http.Request) {

}

func main() {
	flag.StringVar(&CookieName, "cookie", CookieName, "Cookie name to read & store authentication data")
	flag.Parse()

	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/validate", validateHandler)
	if err := http.ListenAndServe(":8000", nil); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server failed: %v\n", err)
	}
}
