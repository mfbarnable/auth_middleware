package password

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
	"gopkg.in/yaml.v3"
)

const configFileName string = "argonParams.yaml"

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
	paramFile := filepath.Join(parent, "config", configFileName)
	fmt.Println(paramFile)
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

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (a *Argon2Generator) Encrypt(password string) ([]byte, error) {
	salt, err := generateRandomBytes(argonParams.SaltLength)
	if err != nil {
		return nil, err
	}
	fmt.Println(argonParams.Iterations)
	hash := argon2.IDKey([]byte(password),
		salt,
		argonParams.Iterations,
		argonParams.Memory,
		argonParams.Parallelism,
		argonParams.KeyLength)

	return hash, nil
}

func (a *Argon2Generator) Decrypt(hashedPassword string) string {
	panic("not implemented") // TODO: Implement
}

func (a *Argon2Generator) Validate(inHashed string, outHashed string) (bool, error) {
	panic("not implemented") // TODO: Implement
}
