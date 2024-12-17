package repository

import (
	"context"

	"github.com/Frozelo/jwtTask/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (ur *UserRepository) FindById(ctx context.Context, userId uuid.UUID) (*models.User, error) {
	query := `SELECT * FROM users WHERE id = $1`
	row := ur.pool.QueryRow(ctx, query, userId)

	var user models.User
	if err := row.Scan(&user); err != nil {
		return nil, errors.Wrap(err, "failed to scan user")
	}

	return &user, nil
}
