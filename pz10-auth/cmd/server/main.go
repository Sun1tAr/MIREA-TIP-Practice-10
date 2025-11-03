package main

import (
	"log"
	"net/http"

	"example.com/pz10-auth/internal/http"
	"example.com/pz10-auth/internal/platform/config"
	"github.com/joho/godotenv"
)

func main() {

	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found")
	}

	cfg := config.Load()
	mux := router.Build(cfg) // см. следующий шаг
	log.Println("listening on", cfg.Port)
	log.Fatal(http.ListenAndServe(cfg.Port, mux))
}
