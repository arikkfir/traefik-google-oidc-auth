package main

import (
	"github.com/arikkfir/traefik-google-oidc-auth/internal"
	"log"
)

func main() {
	log.SetPrefix("")

	config := internal.Config{}
	if err := internal.NewConfig(&config); err != nil {
		log.Fatalf("Failed to configure: %v", err)
	}

	server := internal.NewServer(&config)
	if err := server.Run(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
