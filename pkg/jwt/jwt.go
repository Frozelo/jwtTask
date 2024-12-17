package jwt

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	secretKey string
	issuer    string
}

type Payload struct {
	UserID  string `json:"user_id"`
	IP      string `json:"ip"`
	Session string `json:"session_id"`
	jwt.RegisteredClaims
}

func NewJWTService(secretKey, issuer string) *JWTService {
	return &JWTService{
		secretKey: secretKey,
		issuer:    issuer,
	}
}

func (js *JWTService) GenerateToken(userId, ip, session string) (string, error) {
	payload := Payload{
		UserID:  userId,
		IP:      ip,
		Session: session,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    js.issuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, payload)
	return token.SignedString([]byte(js.secretKey))
}

func (j *JWTService) ValidateToken(tokenString string) (*Payload, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Payload{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Payload)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
