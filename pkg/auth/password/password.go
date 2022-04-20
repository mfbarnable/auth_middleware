package password

type PasswordGenerator interface {
	Encrypt(password string) ([]byte, error)
	Decrypt(hashedPassword string) string
	Validate(inHashed, outHashed string) (bool, error)
}
