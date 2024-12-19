package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"time"

	"github.com/Frozelo/jwtTask/internal/models"
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
	logger     *slog.Logger
}

func NewTokenService(jwtService *jwt.JWTService, userRepo UserRepo, tokenRepo TokenRepo, logger *slog.Logger) *TokenService {
	return &TokenService{jwtService: jwtService, userRepo: userRepo, tokenRepo: tokenRepo, logger: logger}
}

func (ts *TokenService) GenerateTokens(ctx context.Context, userId uuid.UUID, ip string) (string, string, error) {
	ts.logger.Info("Generating tokens", "userId", userId, "ip", ip)
	sessionId := uuid.New().String()

	accessToken, err := ts.jwtService.GenerateToken(userId.String(), ip, sessionId)
	if err != nil {
		ts.logger.Error("Failed to generate access token", "error", err)
		return "", "", errors.Wrap(err, "failed to generate access token")
	}

	refreshToken, err := generateRefreshToken()
	if err != nil {
		ts.logger.Error("Failed to generate refresh token", "error", err)
		return "", "", errors.Wrap(err, "failed to generate refresh token")
	}

	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		ts.logger.Error("Failed to hash refresh token", "error", err)
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
		ts.logger.Error("Failed to save token session", "error", err)
		return "", "", errors.Wrap(err, "failed to create token session")
	}

	ts.logger.Info("Tokens generated successfully", "userId", userId)
	return accessToken, refreshToken, nil
}

func (ts *TokenService) RefreshTokens(ctx context.Context, accessToken, refreshToken, ip string) (string, string, error) {
	ts.logger.Info("Refreshing tokens", "ip", ip)

	payload, err := ts.jwtService.ValidateToken(accessToken)
	if err != nil {
		ts.logger.Error("Invalid access token", "error", err)
		return "", "", errors.Wrap(err, "invalid access token")
	}

	userUUID, err := uuid.Parse(payload.UserID)
	if err != nil {
		ts.logger.Error("Invalid user ID in token", "error", err)
		return "", "", errors.Wrap(err, "invalid user ID in token")
	}

	session, err := ts.tokenRepo.FindTokenSession(ctx, userUUID, payload.Session)
	if err != nil {
		ts.logger.Error("Failed to find token session", "error", err)
		return "", "", errors.Wrap(err, "failed to find token session")
	}

	if time.Now().After(session.ExpiresAt) {
		ts.logger.Warn("Token session has expired", "userId", userUUID)
		return "", "", errors.New("token session has expired")
	}

	if session.Used {
		ts.logger.Warn("Refresh token already used", "userId", userUUID)
		return "", "", errors.New("refresh token has already been used")
	}

	err = bcrypt.CompareHashAndPassword([]byte(session.RefreshTokenHash), []byte(refreshToken))
	if err != nil {
		ts.logger.Error("Invalid refresh token", "error", err)
		return "", "", errors.Wrap(err, "invalid refresh token")
	}

	if session.IP != ip {
		ts.logger.Warn("IP address mismatch", "userId", userUUID)
		user, err := ts.userRepo.FindById(ctx, userUUID)
		if err != nil {
			return "", "", errors.Wrap(err, "failed to find user by ID")
		}

		ts.logger.Info("Warn messga to user", "userId", userUUID, "email", user.Email, "newIP", ip, "oldIp", session.IP)
	}

	err = ts.tokenRepo.MarkAsUsed(ctx, session.Id)
	if err != nil {
		ts.logger.Error("Failed to mark token session as used", "error", err)
		return "", "", errors.Wrap(err, "failed to mark token session as used")
	}

	newAccessToken, newRefreshToken, err := ts.GenerateTokens(ctx, userUUID, ip)
	if err != nil {
		ts.logger.Error("Failed to generate new tokens", "error", err)
		return "", "", errors.Wrap(err, "failed to generate new tokens")
	}

	ts.logger.Info("Tokens refreshed successfully", "userId", userUUID)
	return newAccessToken, newRefreshToken, nil

}

func generateRefreshToken() (string, error) {
	refreshBytes := make([]byte, 32)
	if _, err := rand.Read(refreshBytes); err != nil {
		return "", err
	}

	refreshToken := base64.StdEncoding.EncodeToString(refreshBytes)
	return refreshToken, nil
}
