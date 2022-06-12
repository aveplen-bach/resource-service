package config

import (
	"fmt"

	"github.com/ilyakaznacheev/cleanenv"
)

type (
	Config struct {
		ServerConfig ServerConfig     `yaml:"server"`
		SJWTConfig   SJWTConfig       `yaml:"sjwt"`
		AuthClient   AuthClientConfig `yaml:"auth-client"`
	}

	ServerConfig struct {
		Addr string `yaml:"addr" env-defaul:":8082"`
	}

	SJWTConfig struct {
		Secret string `yaml:"secret" env-default:"mysecret"`
	}

	AuthClientConfig struct {
		Addr string `yaml:"addr" env-default:"localhost:30031"`
	}
)

func ReadConfig(filename string, cfg *Config) error {
	if err := cleanenv.ReadConfig(filename, cfg); err != nil {
		return fmt.Errorf("could not read config: %w", err)
	}
	return nil
}
