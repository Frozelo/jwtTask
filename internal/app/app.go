package app

import (
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Frozelo/jwtTask/internal/config"
	"github.com/Frozelo/jwtTask/internal/controllers"
	"github.com/Frozelo/jwtTask/internal/middleware"
	"github.com/Frozelo/jwtTask/internal/repository"
	"github.com/Frozelo/jwtTask/internal/server"
	"github.com/Frozelo/jwtTask/internal/service"
	"github.com/Frozelo/jwtTask/internal/storage"
	"github.com/Frozelo/jwtTask/pkg/jwt"
	"github.com/gorilla/mux"
)

func Run(dbConfig *config.DatabaseConfig, jwtConfig *config.JWTConfig) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	}))

	dbPool, err := storage.New(dbConfig)

	defer dbPool.Close()
	if err != nil {
		logger.Error("error while connecting to db %v", "error", err)
		os.Exit(1)
	}

	slog.Info("connected to db at user", "user", dbConfig.User)

	userRepo := repository.NewUserRepository(dbPool)
	tokenRepo := repository.NewTokenRepository(dbPool)

	jwtService := jwt.NewJWTService(jwtConfig.SecretKey, jwtConfig.Issuer)
	tokenService := service.NewTokenService(jwtService, userRepo, tokenRepo, logger)

	handler := controllers.NewHandler(tokenService)

	r := mux.NewRouter()

	r.HandleFunc("/refresh", handler.RefreshTokens).Methods("POST")
	r.HandleFunc("/issue", handler.IssueTokens).Methods("POST")

	r.Use(middleware.LoggingMiddleware(logger))

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	logger.Info("starting new servet at port", "port", "8080")
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
