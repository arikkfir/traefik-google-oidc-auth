package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
)

var (
	cookieName   = "X-KFIRS-Auth"
	clientID     = ""
	clientSecret = ""
	tokenURL     = &url.URL{Scheme: "https", Host: "www.googleapis.com", Path: "/oauth2/v3/token"}
	userURL      = &url.URL{Scheme: "https", Host: "www.googleapis.com", Path: "/oauth2/v2/userinfo"}
)

func Nonce() (string, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", nonce), nil
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %+v\n", r.Header)

	origHost := r.Header.Get("X-Forwarded-Host")
	origMethod := r.Header.Get("X-Forwarded-Method")
	origPort := r.Header.Get("X-Forwarded-Port")
	origProto := r.Header.Get("X-Forwarded-Proto")
	//origSourceIP := r.Header.Get("X-Forwarded-For")
	origURI := r.Header.Get("X-Forwarded-Uri")
	if origMethod != "GET" {
		http.Error(w, "Invalid request method", 400)
		return
	} else if origProto != "https" {
		http.Redirect(w, r, "https://"+origHost+":"+origPort+origURI, http.StatusTemporaryRedirect)
		return
	}

	if auth, err := r.Cookie(cookieName); err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			log.Printf("Cookie '%s' not found (user not authenticated) - redirecting to Google OAuth2 page", cookieName)

			nonce, err := Nonce()
			if err != nil {
				log.Printf("Failed to generate nonce: %v", err)
				http.Error(w, "Internal error", 500)
				return
			}

			// TODO: reset CSRF cookie here

			u := url.URL{
				Scheme: "https",
				Host:   "accounts.google.com",
				Path:   "/o/oauth2/auth",
			}
			q := url.Values{}
			q.Set("client_id", clientID)
			q.Set("response_type", "code")
			q.Set("scope", "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email")
			q.Set("prompt", "select_account")
			q.Set("redirect_uri", fmt.Sprintf("%s://%s/auth", origProto, r.Host))
			q.Set("state", fmt.Sprintf("%s:%s", nonce, fmt.Sprintf("%s://%s%s", origProto, origHost, origURI)))
			u.RawQuery = q.Encode()
			loginURL := u.String()

			http.Redirect(w, r, loginURL, http.StatusTemporaryRedirect)
			log.Printf("Redirecting to %s", loginURL)

		} else {
			log.Printf("Failed to read cookie '%s': %v", cookieName, err)
			w.WriteHeader(500)
		}
	} else {
		// TODO: validate the cookie value (probably will need a secret for hashing)
		log.Printf("Cookie '%s' found (user authenticated) - redirecting to original URL; auth info: %s", cookieName, auth.Value)
		w.WriteHeader(200)
	}
}

func validateHandler(_ http.ResponseWriter, _ *http.Request) {

}

func main() {
	flag.StringVar(&cookieName, "cookie", cookieName, "Cookie name to read & store authentication data")
	flag.StringVar(&clientID, "client-id", cookieName, "OAuth application client ID")
	flag.StringVar(&clientSecret, "client-secret", cookieName, "OAuth application client secret")
	flag.Parse()

	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/validate", validateHandler)
	if err := http.ListenAndServe(":8000", nil); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
