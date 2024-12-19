package service_test

import (
	"context"
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

type MockTokenRepo struct {
	mock.Mock
}

func (m *MockUserRepo) FindById(ctx context.Context, userId uuid.UUID) (*models.User, error) {
	args := m.Called(ctx, userId)
	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockTokenRepo) Save(ctx context.Context, session models.TokenSession) error {
	args := m.Called(ctx, session)
	return args.Error(0)
}

func (m *MockTokenRepo) FindTokenSession(ctx context.Context, userID uuid.UUID, sessionID string) (*models.TokenSession, error) {
	args := m.Called(ctx, userID, sessionID)
	return args.Get(0).(*models.TokenSession), args.Error(1)
}

func (m *MockTokenRepo) MarkAsUsed(ctx context.Context, id int64) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func TestTokenService_GenerateTokens(t *testing.T) {
	mockUserRepo := new(MockUserRepo)
	mockTokenRepo := new(MockTokenRepo)

	jwtService := jwt.NewJWTService("test-secret", "test-issuer")
	tokenService := service.NewTokenService(jwtService, mockUserRepo, mockTokenRepo)

	userID := uuid.New()
	ip := "127.0.0.1"

	mockTokenRepo.On("Save", mock.Anything, mock.Anything).Return(nil)

	accessToken, refreshToken, err := tokenService.GenerateTokens(context.Background(), userID, ip)

	assert.NoError(t, err)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)
	mockTokenRepo.AssertExpectations(t)
}

func TestTokenService_RefreshTokens_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepo)
	mockTokenRepo := new(MockTokenRepo)

	jwtService := jwt.NewJWTService("test-secret", "test-issuer")
	tokenService := service.NewTokenService(jwtService, mockUserRepo, mockTokenRepo)

	userID := uuid.New()
	ip := "127.0.0.1"
	sessionID := uuid.New().String()

	accessToken, _ := jwtService.GenerateToken(userID.String(), ip, sessionID)

	refreshToken := "test-refresh-token"
	hashedRefresh, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)

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
	mockTokenRepo.On("Save", mock.Anything, mock.Anything).Return(nil)

	newAccessToken, newRefreshToken, err := tokenService.RefreshTokens(context.Background(), accessToken, refreshToken, ip)

	assert.NoError(t, err)
	assert.NotEmpty(t, newAccessToken)
	assert.NotEmpty(t, newRefreshToken)
	mockTokenRepo.AssertExpectations(t)
}

func TestTokenService_RefreshTokens_InvalidRefreshToken(t *testing.T) {
	mockUserRepo := new(MockUserRepo)
	mockTokenRepo := new(MockTokenRepo)

	jwtService := jwt.NewJWTService("test-secret", "test-issuer")
	tokenService := service.NewTokenService(jwtService, mockUserRepo, mockTokenRepo)

	userID := uuid.New()
	ip := "127.0.0.1"
	sessionID := uuid.New().String()

	accessToken, _ := jwtService.GenerateToken(userID.String(), ip, sessionID)

	refreshToken := "invalid-refresh-token"
	hashedRefresh, _ := bcrypt.GenerateFromPassword([]byte("valid-refresh-token"), bcrypt.DefaultCost)

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

	_, _, err := tokenService.RefreshTokens(context.Background(), accessToken, refreshToken, ip)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid refresh token")
	mockTokenRepo.AssertExpectations(t)
}

func TestTokenService_RefreshTokens_AlreadyUsed(t *testing.T) {
	mockUserRepo := new(MockUserRepo)
	mockTokenRepo := new(MockTokenRepo)

	jwtService := jwt.NewJWTService("test-secret", "test-issuer")
	tokenService := service.NewTokenService(jwtService, mockUserRepo, mockTokenRepo)

	userID := uuid.New()
	ip := "127.0.0.1"
	sessionID := uuid.New().String()

	accessToken, _ := jwtService.GenerateToken(userID.String(), ip, sessionID)

	refreshToken := "test-refresh-token"
	hashedRefresh, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)

	tokenSession := &models.TokenSession{
		Id:               1,
		UserId:           userID,
		RefreshTokenHash: string(hashedRefresh),
		IP:               ip,
		SessionId:        sessionID,
		CreatedAt:        time.Now(),
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		Used:             true,
	}

	mockTokenRepo.On("FindTokenSession", mock.Anything, userID, sessionID).Return(tokenSession, nil)

	_, _, err := tokenService.RefreshTokens(context.Background(), accessToken, refreshToken, ip)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "refresh token has already been used")
	mockTokenRepo.AssertExpectations(t)
}

func TestTokenService_RefreshTokens_WrongIP(t *testing.T) {
	mockUserRepo := new(MockUserRepo)
	mockTokenRepo := new(MockTokenRepo)

	jwtService := jwt.NewJWTService("test-secret", "test-issuer")
	tokenService := service.NewTokenService(jwtService, mockUserRepo, mockTokenRepo)

	userID := uuid.New()
	ip := "127.0.0.1"
	sessionID := uuid.New().String()

	accessToken, _ := jwtService.GenerateToken(userID.String(), ip, sessionID)
	refreshToken := "test-refresh-token"
	hashedRefresh, _ := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)

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

	newIP := "127.0.0.2"
	_, _, err := tokenService.RefreshTokens(context.Background(), accessToken, refreshToken, newIP)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IP address mismatch")
	mockTokenRepo.AssertExpectations(t)

}
