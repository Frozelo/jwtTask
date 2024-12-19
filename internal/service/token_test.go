package service_test

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Frozelo/jwtTask/internal/models"
	"github.com/Frozelo/jwtTask/internal/service"
	"github.com/Frozelo/jwtTask/pkg/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

type MockUserRepo struct {
	mock.Mock
}

func (m *MockUserRepo) FindById(ctx context.Context, userId uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, userId)
	user := args.Get(0)
	if user == nil {
		return nil, args.Error(1)
	}
	return user.(*models.User), args.Error(1)
}

type MockTokenRepo struct {
	mock.Mock
}

func (m *MockTokenRepo) Save(ctx context.Context, session models.TokenSession) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockTokenRepo) FindTokenSession(ctx context.Context, userID uuid.UUID, sessionID string) (*models.TokenSession, error) {
	args := m.Called(ctx, userID, sessionID)
	session := args.Get(0)
	if session == nil {
		return nil, args.Error(1)
	}
	return session.(*models.TokenSession), args.Error(1)
}

func (m *MockTokenRepo) MarkAsUsed(ctx context.Context, id int64) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func setupLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelWarn,
		AddSource: true,
	}))
}

func TestTokenService_GenerateTokens(t *testing.T) {
	mockUserRepo := new(MockUserRepo)
	mockTokenRepo := new(MockTokenRepo)
	logger := setupLogger()
	jwtService := jwt.NewJWTService("test-secret", "test-issuer")
	tokenService := service.NewTokenService(jwtService, mockUserRepo, mockTokenRepo, logger)

	userID := uuid.New()
	ip := "127.0.0.1"

	mockTokenRepo.On("Save", mock.Anything, mock.AnythingOfType("models.TokenSession")).Return(nil)

	accessToken, refreshToken, err := tokenService.GenerateTokens(context.Background(), userID, ip)

	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)
	mockTokenRepo.AssertExpectations(t)
}

func TestTokenService_RefreshTokens_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepo)
	mockTokenRepo := new(MockTokenRepo)
	logger := setupLogger()

	jwtService := jwt.NewJWTService("test-secret", "test-issuer")
	tokenService := service.NewTokenService(jwtService, mockUserRepo, mockTokenRepo, logger)

	userID := uuid.New()
	ip := "127.0.0.1"
	sessionID := uuid.New().String()

	accessToken, err := jwtService.GenerateToken(userID.String(), ip, sessionID)
	assert.NoError(t, err)

	refreshToken := "test-refresh-token"
	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	assert.NoError(t, err)

	tokenSession := &models.TokenSession{
		Id:               1,
		UserId:           userID,
		RefreshTokenHash: string(hashedRefresh),
		IP:               ip,
		SessionId:        sessionID,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		Used:             false,
	}

	mockTokenRepo.On("FindTokenSession", mock.Anything, userID, sessionID).Return(tokenSession, nil)
	mockTokenRepo.On("MarkAsUsed", mock.Anything, tokenSession.Id).Return(nil)
	mockTokenRepo.On("Save", mock.Anything, mock.AnythingOfType("models.TokenSession")).Return(nil)

	newAccessToken, newRefreshToken, err := tokenService.RefreshTokens(context.Background(), accessToken, refreshToken, ip)

	assert.NoError(t, err)
	assert.NotEmpty(t, newAccessToken)
	assert.NotEmpty(t, newRefreshToken)
	mockTokenRepo.AssertExpectations(t)
}

func TestTokenService_RefreshTokens_InvalidRefreshToken(t *testing.T) {
	mockUserRepo := new(MockUserRepo)
	mockTokenRepo := new(MockTokenRepo)
	logger := setupLogger()

	jwtService := jwt.NewJWTService("test-secret", "test-issuer")
	tokenService := service.NewTokenService(jwtService, mockUserRepo, mockTokenRepo, logger)

	userID := uuid.New()
	ip := "127.0.0.1"
	sessionID := uuid.New().String()

	accessToken, err := jwtService.GenerateToken(userID.String(), ip, sessionID)
	assert.NoError(t, err)

	// Refresh token, который не соответствует хешу
	refreshToken := "invalid-refresh-token"
	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte("valid-refresh-token"), bcrypt.DefaultCost)
	assert.NoError(t, err)

	tokenSession := &models.TokenSession{
		Id:               1,
		UserId:           userID,
		RefreshTokenHash: string(hashedRefresh),
		IP:               ip,
		SessionId:        sessionID,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		Used:             false,
	}

	mockTokenRepo.On("FindTokenSession", mock.Anything, userID, sessionID).Return(tokenSession, nil)

	_, _, err = tokenService.RefreshTokens(context.Background(), accessToken, refreshToken, ip)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token")
	mockTokenRepo.AssertExpectations(t)
}

func TestTokenService_RefreshTokens_IPMismatch(t *testing.T) {
	mockUserRepo := new(MockUserRepo)
	mockTokenRepo := new(MockTokenRepo)
	logger := setupLogger()

	jwtService := jwt.NewJWTService("test-secret", "test-issuer")
	tokenService := service.NewTokenService(jwtService, mockUserRepo, mockTokenRepo, logger)

	userID := uuid.New()
	userEmail := "testemail@gmail.com"
	ip := "127.0.0.1"
	newIP := "192.168.0.1"
	sessionID := uuid.New().String()

	accessToken, err := jwtService.GenerateToken(userID.String(), ip, sessionID)
	assert.NoError(t, err)

	refreshToken := "test-refresh-token"
	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	assert.NoError(t, err)

	tokenSession := &models.TokenSession{
		Id:               1,
		UserId:           userID,
		RefreshTokenHash: string(hashedRefresh),
		IP:               ip,
		SessionId:        sessionID,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		Used:             false,
	}

	mockTokenRepo.On("FindTokenSession", mock.Anything, userID, sessionID).Return(tokenSession, nil)
	mockTokenRepo.On("MarkAsUsed", mock.Anything, tokenSession.Id).Return(nil)
	mockTokenRepo.On("Save", mock.Anything, mock.AnythingOfType("models.TokenSession")).Return(nil)
	mockUserRepo.On("FindById", mock.Anything, userID).Return(&models.User{Email: userEmail}, nil)

	_, _, err = tokenService.RefreshTokens(context.Background(), accessToken, refreshToken, newIP)

	assert.NoError(t, err)
	mockTokenRepo.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestTokenService_RefreshTokens_SessionExpired(t *testing.T) {
	mockUserRepo := new(MockUserRepo)
	mockTokenRepo := new(MockTokenRepo)
	logger := setupLogger()
	jwtService := jwt.NewJWTService("test-secret", "test-issuer")
	tokenService := service.NewTokenService(jwtService, mockUserRepo, mockTokenRepo, logger)

	userID := uuid.New()
	ip := "127.0.0.1"
	sessionID := uuid.New().String()

	accessToken, err := jwtService.GenerateToken(userID.String(), ip, sessionID)
	assert.NoError(t, err)

	refreshToken := "test-refresh-token"
	hashedRefresh, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	assert.NoError(t, err)

	tokenSession := &models.TokenSession{
		Id:               1,
		UserId:           userID,
		RefreshTokenHash: string(hashedRefresh),
		IP:               ip,
		SessionId:        sessionID,
		CreatedAt:        time.Now().Add(-25 * time.Hour),
		ExpiresAt:        time.Now().Add(-1 * time.Hour),
		Used:             false,
	}

	mockTokenRepo.On("FindTokenSession", mock.Anything, userID, sessionID).Return(tokenSession, nil)

	_, _, err = tokenService.RefreshTokens(context.Background(), accessToken, refreshToken, ip)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session has expired")
	mockTokenRepo.AssertExpectations(t)
}
