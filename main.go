package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type DatabaseConfig struct {
	Host   string
	Port   string
	User   string
	DbName string
}

type Payload struct {
	UserId   uint   `json:"userId"`
	Email    string `json:"email"`
	ClientIp string `json:"clientIp"`
	jwt.RegisteredClaims
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dbConfig := DatabaseConfig{
		Host:   "localhost",
		User:   "ivansizov",
		Port:   "5432",
		DbName: "jwttask",
	}

	connString := fmt.Sprintf(
		"postgresql://%s@%s:%s/%s",
		dbConfig.User,
		dbConfig.Host,
		dbConfig.Port,
		dbConfig.DbName,
	)

	log.Printf("running db at port %s", dbConfig.Port)
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		log.Fatalf("cant create connection pool: %v\n", err)
	}
	defer pool.Close()

	if err = pool.Ping(ctx); err != nil {
		log.Fatal(err)
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		panic(err)
	}
	hashRefreshToken, err := cryptRefreshToken(refreshToken)
	if err != nil {
		panic(err)
	}

	fmt.Printf("the standart refresh token is %s, the crypt refresh token is %s", refreshToken, hashRefreshToken)
}

func generateRefreshToken() (string, error) {
	refreshBytes := make([]byte, 32)
	if _, err := rand.Read(refreshBytes); err != nil {
		return "", err
	}

	refreshToken := base64.StdEncoding.EncodeToString(refreshBytes)
	return refreshToken, nil
}

func cryptRefreshToken(refreshToken string) (string, error) {
	hashRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", nil
	}

	return string(hashRefreshToken), nil
}

func getPayloadByToken(tokenString string) (*Payload, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Payload{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("very-very-secret"), nil
	})
	if err != nil {
		return nil, err
	}
	if payload, ok := token.Claims.(*Payload); ok && token.Valid {
		return payload, nil
	}
	return nil, fmt.Errorf("invalid token")
}
