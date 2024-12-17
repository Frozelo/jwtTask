package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Frozelo/jwtTask/config"
	"github.com/Frozelo/jwtTask/controllers"
	"github.com/Frozelo/jwtTask/pkg/jwt"
	"github.com/Frozelo/jwtTask/repository"
	"github.com/Frozelo/jwtTask/server"
	"github.com/Frozelo/jwtTask/service"
	"github.com/Frozelo/jwtTask/storage"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func main() {
	dbConfig, jwtConfig, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("error while loading config &v", err)
	}

	testUuid := uuid.New()
	log.Println(testUuid)

	dbPool, err := storage.New(dbConfig)
	defer dbPool.Close()

	userRepo := repository.NewUserRepository(dbPool)
	tokenRepo := repository.NewTokenRepository(dbPool)

	jwtService := jwt.NewJWTService(jwtConfig.SecretKey, jwtConfig.Issuer)
	tokenService := service.NewTokenService(jwtService, userRepo, tokenRepo)

	handler := controllers.NewHandler(tokenService)

	r := mux.NewRouter()

	r.HandleFunc("/issue", handler.IssueTokens).Methods("POST")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	log.Println("startting new servet at port 8080")
	httpServer := server.New(r)

	select {
	case s := <-interrupt:
		log.Printf("app - Run - signal: " + s.String())

	case err = <-httpServer.Notify():
		log.Printf("app - Run - httpServer.Notify: %w", err)

		err = httpServer.Shutdown()
		if err != nil {
			log.Printf("app - Run - httpServer.Shutdown: %w", err)
		}
	}

}
