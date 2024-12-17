package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"time"

	"github.com/Frozelo/jwtTask/models"
	"github.com/Frozelo/jwtTask/pkg/jwt"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type UserRepo interface {
	FindById(ctx context.Context, userId uuid.UUID) (*models.User, error)
}

type TokenRepo interface {
	Save(ctx context.Context, session models.TokenSession) error
	FindTokenSession(ctx context.Context, userID uuid.UUID, sessionID string) (*models.TokenSession, error)
	MarkAsUsed(ctx context.Context, id int64) error
}

type TokenService struct {
	jwtService *jwt.JWTService
	userRepo   UserRepo
	tokenRepo  TokenRepo
}

func NewTokenService(jwtService *jwt.JWTService, userRepo UserRepo, tokenRepo TokenRepo) *TokenService {
	return &TokenService{jwtService: jwtService, userRepo: userRepo, tokenRepo: tokenRepo}
}

func (ts *TokenService) GenerateTokens(ctx context.Context, userId uuid.UUID, ip string) (string, string, error) {
	sessionId := uuid.New().String()

	accessToken, err := ts.jwtService.GenerateToken(userId.String(), ip, sessionId)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to generate access token")
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		return "", "", errors.Wrap(err, "failed to generate refresh token")
	}

	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", "", errors.Wrap(err, "failed to hash refresh token")
	}

	session := models.TokenSession{
		UserId:           userId,
		RefreshTokenHash: string(hashedRefresh),
		IP:               ip,
		SessionId:        sessionId,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		Used:             false,
	}

	if err := ts.tokenRepo.Save(ctx, session); err != nil {
		return "", "", errors.Wrap(err, "failed to create token session")
	}

	return accessToken, refreshToken, nil
}

func generateRefreshToken() (string, error) {
	refreshBytes := make([]byte, 32)
	if _, err := rand.Read(refreshBytes); err != nil {
		return "", err
	}

	refreshToken := base64.StdEncoding.EncodeToString(refreshBytes)
	return refreshToken, nil
}
