package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func envOrDefault(envKey, defaultValue string) string {
	if value := os.Getenv(envKey); value != "" {
		return value
	}
	return defaultValue
}

var (
	clientID       = os.Getenv("CLIENT_ID")
	clientSecret   = os.Getenv("CLIENT_SECRET")
	cookieName     = envOrDefault("COOKIE_NAME", "X-Kfirs-Auth")
	csrfCookieName = envOrDefault("CSRF_COOKIE_NAME", "X-Kfirs-Protect")
	scopes         = envOrDefault("SCOPES", "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email")
	callbackHost   = os.Getenv("CALLBACK_HOST")
	//tokenURL     = &url.URL{Scheme: "https", Host: "www.googleapis.com", Path: "/oauth2/v3/token"}
	//userURL      = &url.URL{Scheme: "https", Host: "www.googleapis.com", Path: "/oauth2/v2/userinfo"}
)

func Nonce() (string, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", nonce), nil
}

func handleValidate(w http.ResponseWriter, r *http.Request) {
	log.Printf("Validate request: %+v\n", r)

	origMethod := r.Header.Get("X-Forwarded-Method")
	origProto := r.Header.Get("X-Forwarded-Proto")
	origHost := r.Header.Get("X-Forwarded-Host")
	origPort := r.Header.Get("X-Forwarded-Port")
	origURI := r.Header.Get("X-Forwarded-Uri")
	//origSourceIP := r.Header.Get("X-Forwarded-For")

	if auth, err := r.Cookie(cookieName); err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			log.Printf("Cookie '%s' not found (user not authenticated) - redirecting to Google OAuth2 page", cookieName)

			if origMethod != "GET" {
				log.Printf("Authentication only allowed for GET requests, not %s; returning HTTP 401 as user is not authenticated", origMethod)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			nonce, err := Nonce()
			if err != nil {
				log.Printf("Failed to generate nonce: %v", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			}

			for _, v := range r.Cookies() {
				if strings.Contains(v.Name, csrfCookieName) {
					http.SetCookie(w, &http.Cookie{
						Name:     v.Name,
						Value:    "",
						Path:     "/",
						Domain:   callbackHost,
						HttpOnly: true,
						Secure:   true,
						Expires:  time.Now().Add(time.Hour * -1),
					})
				}
			}
			http.SetCookie(w, &http.Cookie{
				Name:     csrfCookieName + "_" + nonce[:6],
				Value:    nonce,
				Path:     "/",
				Domain:   callbackHost,
				HttpOnly: true,
				Secure:   true,
				Expires:  time.Now().Add(time.Hour * 1),
			})

			q := url.Values{}
			q.Set("client_id", clientID)
			q.Set("response_type", "code")
			q.Set("scope", scopes)
			q.Set("prompt", "select_account")
			q.Set("redirect_uri", fmt.Sprintf("https://%s/callback", callbackHost))

			state := map[string]string{
				"nonce":  nonce,
				"time":   time.Now().Format(time.RFC3339),
				"target": fmt.Sprintf("%s://%s:%s%s", origProto, origHost, origPort, origURI),
			}
			if stateBytes, err := json.Marshal(state); err != nil {
				log.Printf("Failed to encode state: %v", err)
				http.Error(w, "Internal error", http.StatusInternalServerError)
				return
			} else {
				q.Set("state", string(stateBytes))
			}

			loginURL := url.URL{
				Scheme:   "https",
				Host:     "accounts.google.com",
				Path:     "/o/oauth2/auth",
				RawQuery: q.Encode(),
			}
			http.Redirect(w, r, loginURL.String(), http.StatusTemporaryRedirect)
		} else {
			log.Printf("Failed to read cookie '%s': %v", cookieName, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
	} else {
		// TODO: validate the cookie value (probably will need a secret for hashing)
		log.Printf("Cookie '%s' found (user authenticated) - redirecting to original URL; auth info: %s", cookieName, auth.Value)
		w.WriteHeader(http.StatusOK)
	}
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("Callback request: %+v\n", r)
	w.WriteHeader(http.StatusOK)
}

func main() {
	flag.StringVar(&clientID, "client-id", cookieName, "OAuth application client ID")
	flag.StringVar(&clientSecret, "client-secret", cookieName, "OAuth application client secret")
	flag.StringVar(&cookieName, "cookie", cookieName, "Cookie name to read & store authentication data")
	flag.StringVar(&scopes, "scopes", scopes, "Space-separated OAuth scopes to request from the user")
	flag.StringVar(&callbackHost, "callback-host", cookieName, "External host name assigned to use for OAuth validation (needs to lead back to this service)")
	flag.Parse()
	if clientID == "" {
		fmt.Fprintf(os.Stderr, "OAuth app client ID must be specified\n")
		flag.Usage()
		os.Exit(1)
	} else if clientSecret == "" {
		fmt.Fprintf(os.Stderr, "OAuth app client secret must be specified\n")
		flag.Usage()
		os.Exit(1)
	} else if cookieName == "" {
		fmt.Fprintf(os.Stderr, "Auth cookie name must be specified\n")
		flag.Usage()
		os.Exit(1)
	} else if scopes == "" {
		fmt.Fprintf(os.Stderr, "OAuth scopes must be specified\n")
		flag.Usage()
		os.Exit(1)
	} else if callbackHost == "" {
		fmt.Fprintf(os.Stderr, "Callback host name must be specified\n")
		flag.Usage()
		os.Exit(1)
	}

	http.HandleFunc("/validate", handleValidate)
	http.HandleFunc("/callback", handleCallback)
	// TODO: add logout URL

	if err := http.ListenAndServe(":8000", nil); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
