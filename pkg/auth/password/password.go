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
	Encrypt(password string) (string, error)
	Validate(password string, hash string) (bool, error)
}

func EncryptPassword(password string, generator PasswordGenerator) (string, error) {
	return generator.Encrypt(password)
}

func ValidatePassword(password string, hash string, generator PasswordGenerator) (bool, error) {
	return generator.Validate(password, hash)
}
