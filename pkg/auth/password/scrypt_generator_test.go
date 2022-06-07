package password

import "testing"

func TestEncryptScrypt(t *testing.T) {
	var password string = "some_password"

	scryptGenerator := ScryptGenerator{}
	hash, err := scryptGenerator.Encrypt(password)
	if err != nil {
		t.Error(err)
	}

	t.Logf("Hashed password output %s", hash)
}

func TestDecodeHashScrypt(t *testing.T) {
	var password string = "some_password"

	scryptGenerator := ScryptGenerator{}
	hash, err := scryptGenerator.Encrypt(password)
	if err != nil {
		t.Error(err)
	}
	params, salt, outHash, err := decodeScryptHash(hash)
	if err != nil {
		t.Error(err)
	}

	if params == nil {
		t.Error("Error: scrypt parameters are empty")
	}

	if salt == nil {
		t.Error("Error: salt is empty")
	}

	if outHash == nil {
		t.Error("Error: output hash is empty")
	}
}

func TestValidateScrypt(t *testing.T) {
	var password string = "some_password"

	scryptGenerator := ScryptGenerator{}
	hash, err := scryptGenerator.Encrypt(password)
	if err != nil {
		t.Error(err)
	}

	pass, err := scryptGenerator.Validate(password, hash)
	if err != nil {
		t.Error(err)
	}

	if pass {
		t.Logf("Password matches")
	}
}
