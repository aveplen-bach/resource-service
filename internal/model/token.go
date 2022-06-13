package model

type TokenProtected struct {
	SynBytes  []byte
	Header    Header
	Payload   Payload
	SignBytes []byte
}

type Header struct {
	SignAlg string `json:"alg"`
	EncrAlg string `json:"enc"`
}

type Payload struct {
	UserID int  `json:"userId"`
	Admin  bool `json:"admin"`
}
