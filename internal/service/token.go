package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aveplen-bach/resource-service/internal/client"
	"github.com/aveplen-bach/resource-service/internal/config"
	"github.com/aveplen-bach/resource-service/internal/model"
	"github.com/sirupsen/logrus"
)

type TokenService struct {
	ac  *client.AuthServiceClient
	cfg config.Config
}

func NewTokenService(cfg config.Config, ac *client.AuthServiceClient) *TokenService {
	return &TokenService{
		ac:  ac,
		cfg: cfg,
	}
}

func (t *TokenService) NextToken(token string) (string, error) {
	logrus.Info("getting next token")
	protected, err := unpack(token)
	if err != nil {
		logrus.Error("could not unpack token")
		logrus.Error(err)
		return "", fmt.Errorf("could not unpack token: %w", err)
	}

	logrus.Println(protected)

	signval, err := valSign(
		protected.SignBytes,
		[]byte(t.cfg.SJWTConfig.Secret),
		protected.Header,
		protected.Payload,
	)
	if err != nil {
		logrus.Error("could not validate signature")
		logrus.Error(err)
		return "", fmt.Errorf("could not validate signature: %w", err)
	}
	if !signval {
		logrus.Error("sign of prev token is not correct")
		logrus.Error(err)
		return "", fmt.Errorf("sign of prev token is not correct")
	}

	nsyn, err := t.ac.GetNextSynPackage(uint64(protected.Payload.UserID), protected.SynBytes)
	if err != nil {
		logrus.Error("could not get next syn")
		logrus.Error(err)
		return "", fmt.Errorf("could not get next syn: %w", err)
	}

	protected.SynBytes = nsyn

	repacked, err := pack(protected)
	if err != nil {
		logrus.Error("could not pack token")
		logrus.Error(err)
		return "", fmt.Errorf("could not pack token: %w", err)
	}

	return repacked, nil
}

func (t *TokenService) ExtractPayload(token string) (model.Payload, error) {
	logrus.Info("extracting payload")
	protected, err := unpack(token)
	if err != nil {
		logrus.Error("could not deconstruct token")
		logrus.Error(err)
		return model.Payload{}, fmt.Errorf("could not deconstruct token: %w", err)
	}

	return protected.Payload, nil
}

func pack(protected model.TokenProtected) (string, error) {
	logrus.Info("packing token")
	b64Syn := base64.StdEncoding.EncodeToString(protected.SynBytes)

	headBytes, err := json.Marshal(protected.Header)
	if err != nil {
		logrus.Error("could not marshal header part")
		logrus.Error(err)
		return "", fmt.Errorf("could not marshal header part: %w", err)
	}
	b64Head := base64.StdEncoding.EncodeToString(headBytes)

	pldBytes, err := json.Marshal(protected.Payload)
	if err != nil {
		logrus.Error("could not marshal payload part")
		logrus.Error(err)
		return "", fmt.Errorf("could not marshal payload part: %w", err)
	}
	b64Pld := base64.StdEncoding.EncodeToString(pldBytes)

	b64Sig := base64.StdEncoding.EncodeToString(protected.SignBytes)

	return fmt.Sprintf(
		"%s.%s.%s.%s",
		b64Syn,
		b64Head,
		b64Pld,
		b64Sig,
	), nil
}

func unpack(token string) (model.TokenProtected, error) {
	logrus.Info("unpacking token")
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 4 {
		logrus.Error("token is damaged or of wro")
		return model.TokenProtected{}, fmt.Errorf("token is damaged or of wrong format")
	}

	syn, err := base64.StdEncoding.DecodeString(tokenParts[0])
	if err != nil {
		logrus.Error("could not decode syn")
		logrus.Error(err)
		return model.TokenProtected{}, fmt.Errorf("could not decode syn: %w", err)
	}

	headb, err := base64.StdEncoding.DecodeString(tokenParts[1])
	if err != nil {
		logrus.Error("could not decode header")
		logrus.Error(err)
		return model.TokenProtected{}, fmt.Errorf("could not decode header: %w", err)
	}

	var head model.Header
	if err := json.Unmarshal(headb, &head); err != nil {
		logrus.Error("could not unmarshal header")
		logrus.Error(err)
		return model.TokenProtected{}, fmt.Errorf("could not unmarshal header: %w", err)
	}

	pldb, err := base64.StdEncoding.DecodeString(tokenParts[2])
	if err != nil {
		logrus.Error("could not decode payload")
		logrus.Error(err)
		return model.TokenProtected{}, fmt.Errorf("could not decode payload: %w", err)
	}
	var payload model.Payload
	if err := json.Unmarshal(pldb, &payload); err != nil {
		logrus.Error("could not unmarshal payload")
		logrus.Error(err)
		return model.TokenProtected{}, fmt.Errorf("could not unmarshal payload: %w", err)
	}

	sign, err := base64.StdEncoding.DecodeString(tokenParts[3])
	if err != nil {
		logrus.Error("could not decode sign")
		logrus.Error(err)
		return model.TokenProtected{}, fmt.Errorf("could not decode sign: %w", err)
	}

	return model.TokenProtected{
		SynBytes:  syn,
		Header:    head,
		Payload:   payload,
		SignBytes: sign,
	}, nil
}

func valSign(signature []byte, secret []byte, header model.Header, payload model.Payload) (bool, error) {
	headb, err := json.Marshal(header)
	if err != nil {
		logrus.Error(err)
		return false, fmt.Errorf("could not marshal header: %w", err)
	}

	pldb, err := json.Marshal(payload)
	if err != nil {
		logrus.Error(err)
		return false, fmt.Errorf("could not marshal payload: %w", err)
	}

	h := hmac.New(sha256.New, secret)

	data := strings.Join(b64EncodeSlice([][]byte{headb, pldb}), ".")
	if _, err := h.Write([]byte(data)); err != nil {
		logrus.Error(err)
		return false, fmt.Errorf("could not construct hmac of original values: %w", err)
	}

	return hmac.Equal(signature, h.Sum(nil)), nil
}

func b64EncodeSlice(bytes [][]byte) []string {
	res := make([]string, len(bytes))
	for i := range bytes {
		res[i] = base64.StdEncoding.EncodeToString(bytes[i])
	}
	return res
}
