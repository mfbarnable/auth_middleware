package pki

import (
	"crypto/rand"
	"fmt"
	"log"

	"golang.org/x/crypto/curve25519"
)

func GenerateKey() {
	var random [32]byte
	rand.Read(random[:])
	// Initial should be basepoint or another point created with itself
	out, err := curve25519.X25519(random[:], curve25519.Basepoint)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(out))
}
