package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Payload struct {
	UserId   uint   `json:"userId"`
	Email    string `json:"email"`
	ClientIp string `json:"clientIp"`
	jwt.RegisteredClaims
}

func main() {
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
