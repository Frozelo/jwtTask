package config

import (
	"os"
	"strconv"

	"github.com/pkg/errors"
)

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DbName   string
	SSLMode  string
}

type JWTConfig struct {
	SecretKey string
	Issuer    string
}

func LoadConfig() (*DatabaseConfig, *JWTConfig, error) {
	dbPort, err := strconv.Atoi(getEnv("POSTGRES_PORT", "5432"))
	if err != nil {
		return nil, nil, errors.Wrap(err, "invalid DB_PORT")
	}

	dbConfig := &DatabaseConfig{
		Host:     getEnv("POSTGRES_HOST", "localhost"),
		Port:     dbPort,
		User:     getEnv("POSTGRES_USER", "ivansizov"),
		Password: getEnv("POSTGRES_PASSWORD", ""),
		DbName:   getEnv("POSTGRES_DATABASE_NAME", "jwttask"),
		SSLMode:  getEnv("DB_SSLMODE", "disable"),
	}

	jwtConfig := &JWTConfig{
		SecretKey: getEnv("JWT_SECRET", "supa-dupa-secret-key"),
		Issuer:    getEnv("JWT_ISSUER", "tokenservice"),
	}

	if jwtConfig.SecretKey == "" {
		return nil, nil, errors.New("JWT_SECRET environment variable is not set")
	}

	return dbConfig, jwtConfig, nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}
