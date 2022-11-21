package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Server struct {
	cfg *Config
}

func NewServer(config *Config) *Server {
	server := &Server{cfg: config}
	http.HandleFunc("/verify", server.handleVerifyRequest)
	http.HandleFunc("/callback", server.handleCallbackRequest)
	http.HandleFunc("/logout", server.handleLogout)
	return server
}

func (s *Server) httpError(w http.ResponseWriter, code int, err error) {
	log.Printf("ERROR: %v", err)
	http.Error(w, http.StatusText(code), code)
}

func (s *Server) generateState(r *http.Request) (string, error) {
	nonce, err := Nonce()
	if err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	origProto := r.Header.Get("X-Forwarded-Proto")
	origHost := r.Header.Get("X-Forwarded-Host")
	origPort := r.Header.Get("X-Forwarded-Port")
	origURI := r.Header.Get("X-Forwarded-Uri")

	state := map[string]string{
		"nonce":  nonce,
		"time":   time.Now().Format(time.RFC3339),
		"target": fmt.Sprintf("%s://%s:%s%s", origProto, origHost, origPort, origURI),
	}
	if stateBytes, err := json.Marshal(state); err != nil {
		return "", fmt.Errorf("failed to encoded state as JSON: %w", err)
	} else {
		return string(stateBytes), nil
	}
}

func (s *Server) generateMAC(email string, expires int64) string {
	hash := hmac.New(sha256.New, []byte(s.cfg.HashingSecret))
	hash.Write([]byte(s.cfg.AuthServiceHost))
	hash.Write([]byte(email))
	hash.Write([]byte(fmt.Sprintf("%d", expires)))
	mac := base64.URLEncoding.EncodeToString(hash.Sum(nil))
	return mac
}

func (s *Server) Run() error {
	log.Println("Starting server")
	if err := http.ListenAndServe(":8000", nil); !errors.Is(err, http.ErrServerClosed) {
		return err
	} else {
		return nil
	}
}
