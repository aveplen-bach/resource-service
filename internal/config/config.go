package config

import (
	"fmt"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/sirupsen/logrus"
)

type (
	Config struct {
		ServerConfig ServerConfig     `yaml:"server"`
		SJWTConfig   SJWTConfig       `yaml:"sjwt"`
		AuthClient   AuthClientConfig `yaml:"auth-client"`
	}

	ServerConfig struct {
		Addr string `yaml:"addr" env:"HTTP_LISTEN_ADDR" env-defaul:":8082"`
	}

	SJWTConfig struct {
		Secret string `yaml:"secret" env:"SJWT_SECRET" env-default:"mysecret"`
	}

	AuthClientConfig struct {
		Addr string `yaml:"addr" env:"AUTH_CLIENT_ADDR" env-default:"localhost:30031"`
	}
)

func ReadConfig(filename string, cfg *Config) error {
	logrus.Infof("reading config from %s", filename)
	if err := cleanenv.ReadConfig(filename, cfg); err != nil {
		return fmt.Errorf("could not read config: %w", err)
	}

	logrus.Info("reading env")
	if err := cleanenv.ReadEnv(cfg); err != nil {
		return fmt.Errorf("could not read config: %w", err)
	}
	return nil
}
