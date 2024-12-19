package controllers

import (
	"encoding/json"
	"log"
	"net"
	"net/http"

	"github.com/Frozelo/jwtTask/internal/service"
	"github.com/google/uuid"
)

type Handler struct {
	TokenService *service.TokenService
}

func NewHandler(tokenService *service.TokenService) *Handler {
	return &Handler{TokenService: tokenService}
}

type IssueTokensRequest struct {
	UserId string `json:"user_id"`
}

type IssueTokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokensRequest struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RefreshTokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// IssueTokens
// @Summary      Issue JWT tokens
// @Description  Issues a new access token and a refresh token for the given user_id.
// @Tags         tokens
// @Accept       json
// @Produce      json
// @Param        request body IssueTokensRequest true "User ID"
// @Success      200 {object} IssueTokensResponse
// @Failure      400 {string} string "Invalid request payload or invalid user_id format"
// @Failure      500 {string} string "Failed to generate tokens"
// @Router       /issue [post]
func (h *Handler) IssueTokens(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req IssueTokensRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	userUUID, err := uuid.Parse(req.UserId)
	if err != nil {
		http.Error(w, "Invalid user_id format", http.StatusBadRequest)
		return
	}

	clientIp := getClientIp(r)
	if clientIp == "" {
		http.Error(w, "Unable to determine client IP", http.StatusInternalServerError)
		return
	}

	log.Println(clientIp)

	accessToken, refreshToken, err := h.TokenService.GenerateTokens(ctx, userUUID, clientIp)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	resp := IssueTokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// RefreshTokens
// @Summary      Refresh JWT tokens
// @Description  Refreshes the access token using a valid refresh token. If the IP changes, a warning is logged.
// @Tags         tokens
// @Accept       json
// @Produce      json
// @Param        request body RefreshTokensRequest true "Tokens"
// @Success      200 {object} RefreshTokensResponse
// @Failure      400 {string} string "Invalid request payload"
// @Failure      401 {string} string "Invalid or expired tokens"
// @Router       /refresh [post]
func (h *Handler) RefreshTokens(w http.ResponseWriter, r *http.Request) {
	var req RefreshTokensRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	clientIp := getClientIp(r)
	newAccessToken, newRefreshToken, err := h.TokenService.RefreshTokens(r.Context(), req.AccessToken, req.RefreshToken, clientIp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	resp := RefreshTokensResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func getClientIp(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return ip
}
