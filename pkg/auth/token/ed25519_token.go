package token

type Ed25519Token struct{}

func (e *Ed25519Token) Generate() (string, error) {
	panic("someFunc not implemented")

}

func (e *Ed25519Token) Verify() (bool, error) {
	panic("someFunc not implemented")

}
