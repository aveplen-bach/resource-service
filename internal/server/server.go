package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aveplen-bach/resource-service/internal/client"
	"github.com/aveplen-bach/resource-service/internal/config"
	"github.com/aveplen-bach/resource-service/internal/middleware"
	"github.com/aveplen-bach/resource-service/internal/service"
	"github.com/aveplen-bach/resource-service/protos/auth"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func Start(cfg config.Config) {
	// ============================= auth client ==============================

	timeoutCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	cc, err := grpc.DialContext(timeoutCtx, cfg.AuthClient.Addr,
		grpc.WithBlock(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))

	if err != nil {
		logrus.Warn(fmt.Errorf("failed to connecto to %s: %w", cfg.AuthClient.Addr, err))
	}

	ac := client.NewAuthServiceClient(auth.NewAuthenticationClient(cc))

	logrus.Warn("auth server: ", ac)

	// ================================ service ===============================

	ts := service.NewTokenService(ac)

	// ================================ router ================================

	r := gin.Default()
	r.Use(middleware.Cors())
	r.Use(middleware.IncrementalToken(ts))

	// ================================ routes ================================

	r.GET("/api/resource", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"authenticated": "true",
		})
	})

	// =============================== shutdown ===============================

	srv := &http.Server{
		Addr:    cfg.ServerConfig.Addr,
		Handler: r,
	}

	go func() {
		logrus.Infof("listening: %s\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && errors.Is(err, http.ErrServerClosed) {
			logrus.Warn(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logrus.Warn("shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logrus.Fatal("Server forced to shutdown:", err)
	}

	logrus.Warn("server exited")
}
