package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	pb "github.com/aveplen-bach/resource-service/protos/auth"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Token struct {
	synchronization Synchronization
	header          Header
	payload         Payload
	signature       string
}

type Synchronization struct {
	Syn int `json:"syn"`
	Inc int `json:"inc"`
}

type Header struct {
	Alg string `json:"alg"`
}

type Payload struct {
	UserID    int `json:"userId"`
	SessionID int `json:"sessionId"`
}

func main() {
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cc, err := grpc.DialContext(timeoutCtx, "localhost:8081",
		grpc.WithTransportCredentials(
			insecure.NewCredentials()))

	if err != nil {
		logrus.Fatal(err)
	}

	authClient := pb.NewAuthenticationClient(cc)

	r := gin.Default()

	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	r.Use(func(c *gin.Context) {
		// parse token from request
		authToken := c.GetHeader("Authorization")
		if authToken == "" {
			panic(fmt.Errorf("client does not have authentication header"))
		}

		// split token into parts
		authTokenParts := strings.Split(authToken, ".")
		syn := authTokenParts[0]
		hed := authTokenParts[1]
		pld := authTokenParts[2]
		sgn := authTokenParts[3]

		// verify token signature
		secret := "mysecret"
		data := fmt.Sprintf("%s.%s", hed, pld)
		h := hmac.New(sha256.New, []byte(secret))
		h.Write([]byte(data))
		sha := base64.StdEncoding.EncodeToString(h.Sum(nil))

		if sha != sgn {
			panic(fmt.Errorf("token signature is not verified"))
		}

		// unmarshall pld
		pldBytes, err := base64.StdEncoding.DecodeString(pld)
		if err != nil {
			panic(fmt.Errorf("token payload is not valid base64: %w", err))
		}
		payload := &Payload{}
		if err := json.Unmarshal(pldBytes, payload); err != nil {
			panic(fmt.Errorf("could not unmarshall payload: %w", err))
		}

		c.Next()
		return

		// unmarshall syn
		synBytes, err := base64.StdEncoding.DecodeString(syn)
		if err != nil {
			panic(fmt.Errorf("token synchonization is not valid base64: %w", err))
		}

		// get next syn package
		nextToken, err := authClient.GetNextSynPackage(context.Background(), &pb.SynPackage{
			Id:       uint64(payload.SessionID),
			Contents: synBytes,
		})
		if err != nil {
			panic(fmt.Errorf("auth server returned error when getting next syn package: %w", err))
		}

		// build next token
		newSyn := base64.StdEncoding.EncodeToString(nextToken.Contents)
		newToken := fmt.Sprintf("%s.%s.%s.%s", newSyn, hed, pld, sgn)
		c.Header("Authentication", newToken)

		c.Next()
	})

	r.GET("/api/resource", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"authenticated": "true",
		})
	})

	r.Run(":8083")
}

func Sign(msg, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)

	return hex.EncodeToString(mac.Sum(nil))
}

func Verify(msg, key []byte, hash string) (bool, error) {
	sig, err := hex.DecodeString(hash)
	if err != nil {
		return false, err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(msg)

	return hmac.Equal(sig, mac.Sum(nil)), nil
}
