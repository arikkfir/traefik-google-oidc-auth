package internal

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"
)

var (
	tokenURL = &url.URL{Scheme: "https", Host: "www.googleapis.com", Path: "/oauth2/v3/token"}
	userURL  = &url.URL{Scheme: "https", Host: "www.googleapis.com", Path: "/oauth2/v2/userinfo"}
)

type token struct {
	Token string `json:"access_token"`
}

type user struct {
	Email string `json:"email"`
}

func (s *Server) exchangeCodeForToken(code string) (string, error) {
	form := url.Values{}
	form.Set("client_id", s.cfg.ClientID)
	form.Set("client_secret", s.cfg.ClientSecret)
	form.Set("grant_type", "authorization_code")
	form.Set("redirect_uri", s.cfg.getCallbackURL())
	form.Set("code", code)

	res, err := http.PostForm(tokenURL.String(), form)
	if err != nil {
		return "", fmt.Errorf("failed requesting token: %w", err)
	}
	defer res.Body.Close()

	var t token
	if err := json.NewDecoder(res.Body).Decode(&t); err != nil {
		return "", fmt.Errorf("failed decoding token from response: %w", err)
	}

	return t.Token, nil
}

func (s *Server) getUserEmail(token string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", userURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed creating user HTTP request: %w", err)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed requesting user Email: %w", err)
	}
	defer resp.Body.Close()

	var user user
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("failed decoding user JSON: %w", err)
	} else if user.Email == "" {
		return "", fmt.Errorf("empty Email received for user")
	}

	return user.Email, nil
}

func (s *Server) handleCallbackRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %+v\n", r)

	state := map[string]string{}
	if err := json.Unmarshal([]byte(r.URL.Query().Get("state")), &state); err != nil {
		s.httpError(w, http.StatusBadRequest, fmt.Errorf("failed to unmarshal state JSON: %w", err))
		return
	}

	redirectURL, err := url.Parse(state["target"])
	if err != nil {
		s.httpError(w, http.StatusBadRequest, fmt.Errorf("failed to parse state JSON: %w", err))
		return
	} else if redirectURL.Scheme != "http" && redirectURL.Scheme != "https" {
		s.httpError(w, http.StatusBadRequest, fmt.Errorf("only the HTTPS scheme is allowed for authentication (redirect to HTTPS before applying authentication)"))
		return
	} else if !s.cfg.isAllowedDomain(redirectURL.Host) {
		s.httpError(w, http.StatusForbidden, fmt.Errorf("domain %q is not allowed to authenticate", redirectURL.Host))
		return
	}

	token, err := s.exchangeCodeForToken(r.URL.Query().Get("code"))
	if err != nil {
		s.httpError(w, http.StatusInternalServerError, fmt.Errorf("failed exchanging code for token: %w", err))
		return
	}

	email, err := s.getUserEmail(token)
	if err != nil {
		s.httpError(w, http.StatusInternalServerError, fmt.Errorf("failed fetching user Email with token: %w", err))
		return
	}

	expires := time.Now().Local().Add(time.Hour * 24 * 14)
	mac := s.generateMAC(email, expires.Unix())
	http.SetCookie(w, &http.Cookie{
		Name:     s.cfg.UserCookieName,
		Value:    fmt.Sprintf("%s|%d|%s", mac, expires.Unix(), email),
		Path:     "/",
		Domain:   s.cfg.UserCookieDomain,
		HttpOnly: true,
		Secure:   true,
		Expires:  expires,
	})

	// Redirect
	http.Redirect(w, r, redirectURL.String(), http.StatusTemporaryRedirect)
}
