package main

import (
	"log"

	"github.com/Frozelo/jwtTask/app"
	"github.com/Frozelo/jwtTask/config"
)

func main() {
	dbConfig, jwtConfig, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	app.Run(dbConfig, jwtConfig)
}
