package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/Frozelo/jwtTask/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pkg/errors"
)

func New(cfg *config.DatabaseConfig) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.DbName,
		cfg.SSLMode,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create pgxpool")
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.Wrap(err, "failed to ping db")
	}

	ctx = context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO users (email) VALUES ($1) ON CONFLICT DO NOTHING`, "testgmail@gmail.com"); err != nil {
		pool.Close()
		return nil, errors.Wrap(err, "failed to insert test user")
	}

	return pool, nil
}
