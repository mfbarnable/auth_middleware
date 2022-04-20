package password

import "testing"

func TestEncrypt(t *testing.T) {
	var password string = "some_password"

	argonGenerator := Argon2Generator{}
	hash, err := argonGenerator.Encrypt(password)
	if err != nil {
		t.Error(err)
	}

	t.Logf("Hashed password output %s", hash)
}
