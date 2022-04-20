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

func TestDecodeHash(t *testing.T) {
	var password string = "some_password"

	argonGenerator := Argon2Generator{}
	hash, err := argonGenerator.Encrypt(password)
	if err != nil {
		t.Error(err)
	}
	params, salt, outHash, err := decodeArgonHash(hash)
	if err != nil {
		t.Error(err)
	}

	if params == nil {
		t.Error("Error: argon parameters are empty")
	}

	if salt == nil {
		t.Error("Error: salt is empty")
	}

	if outHash == nil {
		t.Error("Error: output hash is empty")
	}
}

func TestValidate(t *testing.T) {
	var password string = "some_password"

	argonGenerator := Argon2Generator{}
	hash, err := argonGenerator.Encrypt(password)
	if err != nil {
		t.Error(err)
	}

	pass, err := argonGenerator.Validate(password, hash)
	if err != nil {
		t.Error(err)
	}

	if pass {
		t.Logf("Password matches")
	}
}
