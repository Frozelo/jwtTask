package repository

import (
	"context"

	"github.com/Frozelo/jwtTask/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
)

type TokenRepository struct {
	pool *pgxpool.Pool
}

func NewTokenRepository(pool *pgxpool.Pool) *TokenRepository {
	return &TokenRepository{pool: pool}
}

func (tr *TokenRepository) Save(ctx context.Context, session models.TokenSession) error {
	query := `
		INSERT INTO token_sessions (user_id, refresh_hash, ip, session_id, created_at, expires_at, used)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := tr.pool.Exec(ctx, query,
		session.UserId,
		session.RefreshTokenHash,
		session.IP,
		session.SessionId,
		session.CreatedAt,
		session.ExpiresAt,
		session.Used,
	)
	if err != nil {
		return errors.Wrap(err, "failed to insert token session")
	}
	return nil
}

func (tr *TokenRepository) FindTokenSession(ctx context.Context, userID uuid.UUID, sessionID string) (*models.TokenSession, error) {
	query := `
		SELECT id, user_id, refresh_hash, ip, session_id, created_at, expires_at, used
		FROM token_sessions
		WHERE user_id = $1 AND session_id = $2
	`
	row := tr.pool.QueryRow(ctx, query, userID, sessionID)

	var session models.TokenSession
	err := row.Scan(
		&session.Id,
		&session.UserId,
		&session.RefreshTokenHash,
		&session.IP,
		&session.SessionId,
		&session.CreatedAt,
		&session.ExpiresAt,
		&session.Used,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to scan token session")
	}

	return &session, nil
}

func (tr *TokenRepository) MarkAsUsed(ctx context.Context, id int64) error {
	query := `UPDATE token_sessions SET used = TRUE WHERE id = $1`

	_, err := tr.pool.Exec(ctx, query, id)
	if err != nil {
		return errors.Wrap(err, "failed to scan token session")
	}

	return nil
}
