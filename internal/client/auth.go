package client

import (
	"context"
	"fmt"

	"github.com/aveplen-bach/resource-service/protos/auth"
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
	res, err := ac.client.GetNextSynPackage(context.Background(), &auth.SynPackage{
		Id:       userID,
		Contents: syn,
	})

	if err != nil {
		return nil, fmt.Errorf("could not fetch new syn: %w", err)
	}

	return res.Contents, nil
}
