package password

import "crypto/rand"

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

type PasswordGenerator interface {
	Encrypt(password string) ([]byte, error)
	Validate(password, hash []byte) (bool, error)
}
