package password

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

const argonConfigFileName string = "argonParams.yaml"

type ArgonParams struct {
	Memory      uint32 `yaml:"memory"`
	Iterations  uint32 `yaml:"iterations"`
	Parallelism uint8  `yaml:"parallelism"`
	SaltLength  uint32 `yaml:"saltLength"`
	KeyLength   uint32 `yaml:"keyLength"`
}

var argonParams ArgonParams

func init() {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	parent := filepath.Dir(wd)
	parent = filepath.Dir(parent)
	parent = filepath.Dir(parent)
	paramFile := filepath.Join(parent, "config", argonConfigFileName)
	content, err := ioutil.ReadFile(paramFile)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(content, &argonParams)
	if err != nil {
		log.Fatal(err)
	}
}

type Argon2Generator struct{}

func decodeArgonHash(encodedHash string) (param *ArgonParams, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p := &ArgonParams{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}

func (a *Argon2Generator) Encrypt(password string) (string, error) {
	salt, err := generateRandomBytes(argonParams.SaltLength)
	if err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(password),
		salt,
		argonParams.Iterations,
		argonParams.Memory,
		argonParams.Parallelism,
		argonParams.KeyLength)
	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonParams.Memory, argonParams.Iterations,
		argonParams.Parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func (a *Argon2Generator) Validate(password string, hash string) (bool, error) {
	params, salt, hashed, err := decodeArgonHash(hash)
	if err != nil {
		return false, err
	}

	passwdHash := argon2.IDKey([]byte(password), salt, params.Iterations,
		params.Memory, params.Parallelism, params.KeyLength)

	if subtle.ConstantTimeCompare(hashed, passwdHash) == 1 {
		return true, nil
	}

	return false, nil
}
