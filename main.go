package main

import (
	"github.com/golang-jwt/jwt/v5"
	"log"
	"time"
)

func main() {

	userId := "123213213"
	clientUp := "127.0.0.1"
	payload := jwt.MapClaims{
		"id":  userId,
		"ip":  clientUp,
		"exp": time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, payload)
	signedToken, err := token.SignedString([]byte("very-very-secret"))
	if err != nil {
		panic(err)
	}
	log.Println(signedToken)
}
