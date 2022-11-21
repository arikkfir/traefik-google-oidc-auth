package internal

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func (s *Server) redirectToGoogleAuth(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Forwarded-Method") != "GET" {
		s.httpError(w, http.StatusUnauthorized, fmt.Errorf("only GET requests are allowed"))
		return
	}

	state, err := s.generateState(r)
	if err != nil {
		s.httpError(w, http.StatusInternalServerError, fmt.Errorf("failed to generate state as JSON: %w", err))
		return
	}

	q := url.Values{}
	q.Set("client_id", s.cfg.ClientID)
	q.Set("response_type", "code")
	q.Set("scope", s.cfg.Scopes)
	q.Set("prompt", "select_account")
	q.Set("redirect_uri", s.cfg.getCallbackURL())
	q.Set("state", state)
	loginURL := url.URL{
		Scheme:   "https",
		Host:     "accounts.google.com",
		Path:     "/o/oauth2/auth",
		RawQuery: q.Encode(),
	}
	http.Redirect(w, r, loginURL.String(), http.StatusTemporaryRedirect)
}

func (s *Server) validateCookie(w http.ResponseWriter, c *http.Cookie) {
	parts := strings.Split(c.Value, "|")
	if len(parts) != 3 {
		s.httpError(w, http.StatusBadRequest, fmt.Errorf("invalid cookie value (expected 3 tokens): %s", c.Value))
		return
	}

	cookieMAC := parts[0]
	cookieExpires, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		s.httpError(w, http.StatusBadRequest, fmt.Errorf("invalid cookie 2nd token (expires) value: %s", c.Value))
		return
	} else if time.Unix(cookieExpires, 0).Before(time.Now()) {
		s.httpError(w, http.StatusBadRequest, fmt.Errorf("expired authentication: %s", c.Value))
		return
	}
	cookieEmail := parts[2]

	expectedMAC := s.generateMAC(cookieEmail, cookieExpires)
	if !hmac.Equal([]byte(cookieMAC), []byte(expectedMAC)) {
		s.httpError(w, http.StatusBadRequest, fmt.Errorf("incorrect MAC in cookie: %s", c.Value))
		return
	}

	userParts := strings.Split(cookieEmail, "@")
	if len(userParts) != 2 {
		s.httpError(w, http.StatusBadRequest, fmt.Errorf("invalid user Email: %s", c.Value))
		return
	} else if !s.cfg.isAllowedDomain(userParts[1]) {
		s.httpError(w, http.StatusForbidden, fmt.Errorf("domain '%s' is not allowed to authenticate", userParts[1]))
		return
	}

	w.Header().Set("X-Forwarded-User", cookieEmail)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleVerifyRequest(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %+v\n", r)
	if c, err := r.Cookie(s.cfg.UserCookieName); err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			s.redirectToGoogleAuth(w, r)
		} else {
			s.httpError(w, http.StatusBadRequest, fmt.Errorf("failed to read cookie: %w", err))
			return
		}
	} else {
		s.validateCookie(w, c)
	}
}
