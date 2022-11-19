package main

import (
	"errors"
	"log"
	"net/http"
)

func authHandler(w http.ResponseWriter, r *http.Request) {
	origMethod := r.Header.Get("X-Forwarded-Method")
	origProto := r.Header.Get("X-Forwarded-Proto")
	origHost := r.Header.Get("X-Forwarded-Host")
	origURI := r.Header.Get("X-Forwarded-Uri")
	origSourceIP := r.Header.Get("X-Forwarded-For")
	log.Printf("Auth: %s | %s | %s | %s | %s", origMethod, origProto, origHost, origURI, origSourceIP)
	w.WriteHeader(200)
}

func validateHandler(w http.ResponseWriter, r *http.Request) {

}

func main() {
	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/validate", validateHandler)
	if err := http.ListenAndServe(":8000", nil); !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server failed: %v\n", err)
	}
}
