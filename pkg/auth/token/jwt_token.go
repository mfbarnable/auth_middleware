package token

type JwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type JwtPayload struct {
	Iss    string `json:"iss"`
	Exp    int64  `json:"exp"`
	Iat    int64  `json:"iat"`
	Sub    int64  `json:"sub"`
	Params map[string]interface{}
}

type JwtToken struct {
	Header  JwtHeader
	Payload JwtPayload
}

type IJwtToken interface {
	Init()
	Generate(secret []byte) (string, error)
	Verify(token *JwtToken, secret []byte) (bool, error)
}
