package main

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type Payload struct {
	UserId   uint   `json:"userId"`
	Email    string `json:"email"`
	ClientIp string `json:"clientIp"`
	jwt.RegisteredClaims
}

func main() {
	expDate := time.Now().Add(1 * time.Hour)
	payload := &Payload{
		UserId:   1,
		Email:    "test@gmail.com",
		ClientIp: "127.0.0.1",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expDate),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	tokenString, err := token.SignedString([]byte("very-very-secret"))
	if err != nil {
		panic(err)
	}

	payloadInfo, err := getPayloadByToken(tokenString)
	if err != nil {
		panic(err)
	}
	fmt.Println(payloadInfo)

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
