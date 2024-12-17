package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/Frozelo/jwtTask/service"
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
	Ip     string `json:"ip"`
}

type IssueTokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

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
	}

	accessToken, refreshToken, err := h.TokenService.GenerateTokens(ctx, userUUID, req.Ip)
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
