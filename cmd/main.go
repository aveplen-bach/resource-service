package main

import (
	"github.com/sirupsen/logrus"

	"github.com/aveplen-bach/resource-service/internal/config"
	"github.com/aveplen-bach/resource-service/internal/server"
)

func main() {
	var cfg config.Config
	if err := config.ReadConfig("resource-service.yaml", &cfg); err != nil {
		logrus.Fatal(err)
	}
	server.Start(cfg)
}
