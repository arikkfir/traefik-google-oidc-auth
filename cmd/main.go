package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/Jeffail/gabs/v2"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	clientID     = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	cookieName   = os.Getenv("COOKIE_NAME")
	//csrfCookieName     = os.Getenv("CSRF_COOKIE_NAME")
	scopes             = envOrDefault("SCOPES", "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email")
	oauthHost          = os.Getenv("OAUTH_HOST")
	tokenURL           = &url.URL{Scheme: "https", Host: "www.googleapis.com", Path: "/oauth2/v3/token"}
	userURL            = &url.URL{Scheme: "https", Host: "www.googleapis.com", Path: "/oauth2/v2/userinfo"}
	signingSecret      = os.Getenv("SIGNING_SECRET")
	allowedUserDomains []string
)

type token struct {
	Token string `json:"access_token"`
}

func envOrDefault(envKey, defaultValue string) string {
	if value := os.Getenv(envKey); value != "" {
		return value
	}
	return defaultValue
}

func Nonce() (string, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", nonce), nil
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	origMethod := r.Header.Get("X-Forwarded-Method")
	origProto := r.Header.Get("X-Forwarded-Proto")
	origHost := r.Header.Get("X-Forwarded-Host")
	origPort := r.Header.Get("X-Forwarded-Port")
	origURI := r.Header.Get("X-Forwarded-Uri")

	if c, err := r.Cookie(cookieName); err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			log.Printf("Cookie '%s' not found (user not authenticated) - redirecting to Google OAuth2 page", cookieName)

			if origMethod != "GET" {
				log.Printf("Authentication only allowed for GET requests, not %s; returning HTTP 401 as user is not authenticated", origMethod)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			nonce, err := Nonce()
			if err != nil {
				log.Printf("Failed to generate nonce: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}

			// TODO: add CSRF cookie

			q := url.Values{}
			q.Set("client_id", clientID)
			q.Set("response_type", "code")
			q.Set("scope", scopes)
			q.Set("prompt", "select_account")
			q.Set("redirect_uri", fmt.Sprintf("https://%s/callback", oauthHost))

			state := map[string]string{
				"nonce":  nonce,
				"time":   time.Now().Format(time.RFC3339),
				"target": fmt.Sprintf("%s://%s:%s%s", origProto, origHost, origPort, origURI),
			}
			if stateBytes, err := json.Marshal(state); err != nil {
				log.Printf("Failed to encode state: %v", err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	} else {
		log.Printf("Cookie '%s' found (user authenticated) - redirecting to original URL; auth info: %s", cookieName, c.Value)

		parts := strings.Split(c.Value, "|")

		if len(parts) != 3 {
			log.Printf("Failed to parse cookie: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		mac, err := base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			log.Printf("Failed to parse signature: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		hash := hmac.New(sha256.New, []byte(signingSecret))
		hash.Write([]byte(oauthHost))
		hash.Write([]byte(parts[2]))
		hash.Write([]byte(parts[1]))
		expectedSignature := base64.URLEncoding.EncodeToString(hash.Sum(nil))
		expected, err := base64.URLEncoding.DecodeString(expectedSignature)
		if err != nil {
			log.Printf("Failed to generate signature: %v", err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		// Valid token?
		if !hmac.Equal(mac, expected) {
			log.Printf("Bad MAC signature: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		expires, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			log.Printf("Bad expiry in cookie: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		// Has it expired?
		if time.Unix(expires, 0).Before(time.Now()) {
			log.Printf("Expired auth cookie: %v", err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		// Looks valid
		user := parts[2]
		userParts := strings.Split(user, "@")
		if len(userParts) < 2 {
			log.Printf("Illegal user: %s", user)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		emailDomain := strings.ToLower(parts[1])
		domainAllowed := false
		for _, domain := range allowedUserDomains {
			if domain == emailDomain {
				domainAllowed = true
			}
		}
		if !domainAllowed {
			log.Printf("Forbidden domain: %s", emailDomain)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		w.Header().Set("X-Forwarded-User", user)
		w.WriteHeader(http.StatusOK)
	}
}

func handleAuthCallback(w http.ResponseWriter, r *http.Request) {
	log.Printf("Callback request: %+v\n", r)

	state := map[string]string{}
	if err := json.Unmarshal([]byte(r.URL.Query().Get("state")), &state); err != nil {
		log.Printf("Failed to decode state: %v", err)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Validate redirect
	redirectURL, err := url.Parse(state["target"])
	if err != nil {
		log.Printf("Missing target URL: %v", state)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	} else if redirectURL.Scheme != "http" && redirectURL.Scheme != "https" {
		log.Printf("Invalid redirect URL scheme: %v", redirectURL)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// TODO: validate target URL host is in the list of allowed hosts

	// Exchange code for token
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", fmt.Sprintf("https://%s/callback", oauthHost))
	form.Set("code", r.URL.Query().Get("code"))
	res, err := http.PostForm(tokenURL.String(), form)
	if err != nil {
		log.Printf("Failed requesting token: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var t token
	if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
		log.Printf("Failed decoding token JSON: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else if err := res.Body.Close(); err != nil {
		log.Printf("Failed to close response body: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	// Get user
	client := &http.Client{}
	req, err := http.NewRequest("GET", userURL.String(), nil)
	if err != nil {
		log.Printf("Failed to build request for user: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var user string
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", t.Token))
	if resp, err := client.Do(req); err != nil {
		log.Printf("Failed requesting user: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else if j, err := gabs.ParseJSONBuffer(resp.Body); err != nil {
		log.Printf("Failed parsing user JSON: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else if err := resp.Body.Close(); err != nil {
		log.Printf("Failed closing HTTP user response body: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else if !j.ExistsP("email") {
		log.Printf("Failed to find user path in user JSON '%s': %v", j.String(), err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	} else {
		log.Printf("User: %v", j.String())
		user = fmt.Sprintf("%v", j.Path("email").Data())
	}

	// Generate cookie
	expires := time.Now().Local().Add(time.Hour * 24 * 14)
	hash := hmac.New(sha256.New, []byte(signingSecret))
	hash.Write([]byte(oauthHost))
	hash.Write([]byte(user))
	hash.Write([]byte(fmt.Sprintf("%d", expires.Unix())))
	mac := base64.URLEncoding.EncodeToString(hash.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), user),
		Path:     "/",
		Domain:   strings.Split(redirectURL.Host, ":")[0],
		HttpOnly: true,
		Secure:   true,
		Expires:  expires,
	})

	// Redirect
	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}

func main() {
	flag.StringVar(&clientID, "client-id", clientID, "OAuth application client ID")
	flag.StringVar(&clientSecret, "client-secret", clientSecret, "OAuth application client secret")
	flag.StringVar(&cookieName, "cookie", cookieName, "Cookie name to read & store authentication data")
	flag.StringVar(&scopes, "scopes", scopes, "Space-separated OAuth scopes to request from the user")
	flag.StringVar(&oauthHost, "oauth-host", oauthHost, "External host name assigned to use for OAuth validation (needs to lead back to this service)")
	flag.StringVar(&signingSecret, "signing-secret", signingSecret, "Secret used for signing user cookie")
	flag.Func("allowed-user-domains", "Comma-separated list of allowed user domains", func(s string) error {
		if s == "" {
			return fmt.Errorf("allowed user domains is required")
		}
		allowedUserDomains = strings.Split(s, ",")
		return nil
	})

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
	} else if oauthHost == "" {
		fmt.Fprintf(os.Stderr, "Callback host name must be specified\n")
		flag.Usage()
		os.Exit(1)
	} else if signingSecret == "" {
		fmt.Fprintf(os.Stderr, "User cookie signing secret must be specified\n")
		flag.Usage()
		os.Exit(1)
	} else if len(allowedUserDomains) == 0 {
		allowedUserDomainsEnv := os.Getenv("ALLOWED_USER_DOMAINS")
		if allowedUserDomainsEnv != "" {
			allowedUserDomains = strings.Split(allowedUserDomainsEnv, ",")
		} else {
			fmt.Fprintf(os.Stderr, "Allowed user domains is required\n")
			flag.Usage()
			os.Exit(1)
		}
	}

	http.HandleFunc("/verify", handleVerify)
	http.HandleFunc("/callback", handleAuthCallback)
	// TODO: add logout URL

	if err := http.ListenAndServe(":8000", nil); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
