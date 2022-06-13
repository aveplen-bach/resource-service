package service

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aveplen-bach/resource-service/internal/client"
	"github.com/aveplen-bach/resource-service/internal/model"
	"github.com/sirupsen/logrus"
)

type TokenService struct {
	ac *client.AuthServiceClient
}

func NewTokenService(ac *client.AuthServiceClient) *TokenService {
	return &TokenService{
		ac: ac,
	}
}

func (t *TokenService) NextToken(token string) (string, error) {
	logrus.Info("getting next token")
	protected, err := unpack(token)
	if err != nil {
		logrus.Warnf("could not unpack token: %w", err)
		return "", fmt.Errorf("could not unpack token: %w", err)
	}

	nsyn, err := t.ac.GetNextSynPackage(uint64(protected.Payload.UserID), protected.SynchronizationBytes)
	if err != nil {
		logrus.Warnf("could not get next syn: %w", err)
		return "", fmt.Errorf("could not get next syn: %w", err)
	}

	protected.SynchronizationBytes = nsyn

	repacked, err := pack(protected)
	if err != nil {
		logrus.Warnf("could not pack token: %w", err)
		return "", fmt.Errorf("could not pack token: %w", err)
	}

	return repacked, nil
}

func (t *TokenService) ValidateToken(token string) (bool, error) {
	logrus.Info("validatin token")
	protected, err := unpack(token)
	if err != nil {
		logrus.Warnf("could not unpack token: %w", err)
		return false, fmt.Errorf("could not unpack token: %w", err)
	}

	logrus.Warn("Validate token not implemented", protected)

	return true, nil
}

func (t *TokenService) ExtractPayload(token string) (model.Payload, error) {
	logrus.Info("extracting payload")
	protected, err := unpack(token)
	if err != nil {
		logrus.Warnf("could not deconstruct token: %w", err)
		return model.Payload{}, fmt.Errorf("could not deconstruct token: %w", err)
	}

	return protected.Payload, nil
}

func pack(protected model.TokenProtected) (string, error) {
	logrus.Info("packing token")
	b64Syn := base64.StdEncoding.EncodeToString(protected.SynchronizationBytes)

	headBytes, err := json.Marshal(protected.Header)
	if err != nil {
		logrus.Warnf("could not marshal header part: %w", err)
		return "", fmt.Errorf("could not marshal header part: %w", err)
	}
	b64Head := base64.StdEncoding.EncodeToString(headBytes)

	pldBytes, err := json.Marshal(protected.Payload)
	if err != nil {
		logrus.Warnf("could not marshal payload part: %w", err)
		return "", fmt.Errorf("could not marshal payload part: %w", err)
	}
	b64Pld := base64.StdEncoding.EncodeToString(pldBytes)

	b64Sig := base64.StdEncoding.EncodeToString(protected.SignatureBytes)

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
		logrus.Warnf("token is damaged or of wrong format")
		return model.TokenProtected{}, fmt.Errorf("token is damaged or of wrong format")
	}

	syn, err := base64.StdEncoding.DecodeString(tokenParts[0])
	if err != nil {
		logrus.Warnf("could not decode syn: %w", err)
		return model.TokenProtected{}, fmt.Errorf("could not decode syn: %w", err)
	}

	headb, err := base64.StdEncoding.DecodeString(tokenParts[1])
	if err != nil {
		logrus.Warnf("could not decode header: %w", err)
		return model.TokenProtected{}, fmt.Errorf("could not decode header: %w", err)
	}

	var head model.Header
	if err := json.Unmarshal(headb, &head); err != nil {
		logrus.Warnf("could not unmarshal header: %w", err)
		return model.TokenProtected{}, fmt.Errorf("could not unmarshal header: %w", err)
	}

	pldb, err := base64.StdEncoding.DecodeString(tokenParts[2])
	if err != nil {
		logrus.Warnf("could not decode payload: %w", err)
		return model.TokenProtected{}, fmt.Errorf("could not decode payload: %w", err)
	}
	var payload model.Payload
	if err := json.Unmarshal(pldb, &payload); err != nil {
		logrus.Warnf("could not unmarshal payload: %w", err)
		return model.TokenProtected{}, fmt.Errorf("could not unmarshal payload: %w", err)
	}

	sign, err := base64.StdEncoding.DecodeString(tokenParts[3])
	if err != nil {
		logrus.Warnf("could not decode sign: %w", err)
		return model.TokenProtected{}, fmt.Errorf("could not decode sign: %w", err)
	}

	return model.TokenProtected{
		SynchronizationBytes: syn,
		Header:               head,
		Payload:              payload,
		SignatureBytes:       sign,
	}, nil
}
