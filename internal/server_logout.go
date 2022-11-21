package internal

import (
	"log"
	"net/http"
)

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request: %+v\n", r)
	// TODO: implement HandleLogout
}
