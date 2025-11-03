package config

import (
	"log"
	"os"
)

type Config struct {
	Port      string
	JWTSecret []byte
	// JWTTTL больше не нужен здесь
}

func Load() Config {
	port := os.Getenv("APP_PORT")
	if port == "" {
		port = "8080"
	}

	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET is required")
	}

	return Config{Port: ":" + port, JWTSecret: []byte(secret)}
}
