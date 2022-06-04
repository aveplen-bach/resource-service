package model

type TokenProtected struct {
	SynchronizationBytes []byte
	Header               Header
	Payload              Payload
	SignatureBytes       []byte
}

type Header struct {
	SignatureAlg  string `json:"alg"`
	EncryptionAlg string `json:"enc"`
}

type Payload struct {
	UserID    int `json:"userId"`
	SessionID int `json:"sessionId"`
}
