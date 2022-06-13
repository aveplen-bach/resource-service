package client

import (
	"context"
	"fmt"

	"github.com/aveplen-bach/resource-service/protos/auth"
	"github.com/sirupsen/logrus"
)

type AuthServiceClient struct {
	client auth.AuthenticationClient
}

func NewAuthServiceClient(client auth.AuthenticationClient) *AuthServiceClient {
	return &AuthServiceClient{
		client: client,
	}
}

func (ac *AuthServiceClient) GetNextSynPackage(userID uint64, syn []byte) ([]byte, error) {
	logrus.Info("getting next syn from auth service")
	res, err := ac.client.GetNextSynPackage(context.Background(), &auth.SynPackage{
		Id:       userID,
		Contents: syn,
	})

	if err != nil {
		logrus.Warnf("could not fetch new syn: %w", err)
		return nil, fmt.Errorf("could not fetch new syn: %w", err)
	}

	return res.Contents, nil
}
