package internal

import (
	"crypto/rand"
	"fmt"
)

func Nonce() (string, error) {
	nonce := make([]byte, 16)
	_, err := rand.Read(nonce)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", nonce), nil
}
