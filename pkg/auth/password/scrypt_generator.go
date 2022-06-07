package password

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/scrypt"
	"gopkg.in/yaml.v3"
)

const scryptVerion int = 2
const scryptConfigFileName string = "scryptParams.yaml"

type SCryptParams struct {
	Memory      int `yaml:"memory"`
	Iterations  int `yaml:"iterations"`
	Parallelism int `yaml:"parallelism"`
	SaltLength  int `yaml:"saltLength"`
	KeyLength   int `yaml:"keyLength"`
}

var scryptParams SCryptParams

type ScryptGenerator struct {
}

func init() {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	parent := filepath.Dir(wd)
	parent = filepath.Dir(parent)
	parent = filepath.Dir(parent)
	paramFile := filepath.Join(parent, "config", scryptConfigFileName)
	content, err := ioutil.ReadFile(paramFile)
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(content, &scryptParams)
	if err != nil {
		log.Fatal(err)
	}
}

func decodeScryptHash(encodedHash string) (param *SCryptParams, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != scryptVerion {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p := &SCryptParams{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory,
		&p.Iterations, &p.Parallelism)

	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.SaltLength = len(salt)

	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.KeyLength = len(hash)

	return p, salt, hash, nil
}

func (s *ScryptGenerator) Encrypt(password string) (string, error) {
	salt, err := generateRandomBytes(uint32(scryptParams.SaltLength))
	if err != nil {
		return "", err
	}

	hash, err := scrypt.Key([]byte(password), salt, scryptParams.Memory,
		scryptParams.Iterations, scryptParams.Parallelism,
		scryptParams.KeyLength)
	if err != nil {
		return "", err
	}

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$scrypt$v=%d$m=%d,t=%d,p=%d$%s$%s",
		scryptVerion, scryptParams.Memory, scryptParams.Iterations,
		scryptParams.Parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

func (s *ScryptGenerator) Validate(password string, hash string) (bool, error) {
	params, salt, hashed, err := decodeScryptHash(hash)
	if err != nil {
		return false, err
	}

	passwdHash, err := scrypt.Key([]byte(password), salt, params.Memory,
		params.Iterations, params.Parallelism,
		params.KeyLength)
	if err != nil {
		return false, err
	}

	if subtle.ConstantTimeCompare(hashed, passwdHash) == 1 {
		return true, nil
	}

	return false, nil
}
