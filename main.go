package main

import (
	"log"
	"log/slog"
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
	"github.com/gorilla/mux"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		AddSource: true,
	}))

	dbConfig, jwtConfig, err := config.LoadConfig()
	if err != nil {
		logger.Error("error while loading config %v", "error", err)
	}
	slog.Info("config loaded")

	dbPool, err := storage.New(dbConfig)
	defer dbPool.Close()
	if err != nil {
		logger.Error("error while connecting to db %v", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()
	slog.Info("connected to db at user", "user", dbConfig.User)

	userRepo := repository.NewUserRepository(dbPool)
	tokenRepo := repository.NewTokenRepository(dbPool)

	jwtService := jwt.NewJWTService(jwtConfig.SecretKey, jwtConfig.Issuer)
	tokenService := service.NewTokenService(jwtService, userRepo, tokenRepo)

	handler := controllers.NewHandler(tokenService)

	r := mux.NewRouter()

	r.HandleFunc("/refresh", handler.RefreshTokens).Methods("POST")
	r.HandleFunc("/issue", handler.IssueTokens).Methods("POST")

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	logger.Info("startting new servet at port", "port", "8080")
	httpServer := server.New(r)

	select {
	case s := <-interrupt:
		log.Printf("app - Run - signal %s", s.String())

	case err = <-httpServer.Notify():
		log.Printf("app - Run - httpServer.Notify: %v", err)

		err = httpServer.Shutdown()
		if err != nil {
			log.Printf("app - Run - httpServer.Shutdown: %v", err)
		}
	}

}
