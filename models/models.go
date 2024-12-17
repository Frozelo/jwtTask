package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	Id    uuid.UUID
	Email string
}

type TokenSession struct {
	Id               int64
	UserId           uuid.UUID
	RefreshTokenHash string
	IP               string
	SessionId        string
	CreatedAt        time.Time
	ExpiresAt        time.Time
	Used             bool
}
