package password

type PasswordGenerator interface {
	Encrypt(password string) ([]byte, error)
	Validate(password, hash []byte) (bool, error)
}
