package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	conf "github.com/JMURv/avito/internal/config"
	"github.com/JMURv/avito/internal/repo"
	"github.com/JMURv/avito/pkg/model"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/opentracing/opentracing-go"
	"go.uber.org/zap"
	"path/filepath"
	"strings"
)

type Repository struct {
	conn *sql.DB
}

func New(conf *conf.DBConfig) *Repository {
	conn, err := sql.Open(
		"postgres", fmt.Sprintf(
			"postgres://%s:%s@%s:%d/%s?sslmode=disable",
			conf.User,
			conf.Password,
			conf.Host,
			conf.Port,
			conf.Database,
		),
	)
	if err != nil {
		zap.L().Fatal("Failed to connect to the database", zap.Error(err))
	}

	if err = conn.Ping(); err != nil {
		zap.L().Fatal("Failed to ping the database", zap.Error(err))
	}

	if err = applyMigrations(conn, conf); err != nil {
		zap.L().Fatal("Failed to apply migrations", zap.Error(err))
	}

	return &Repository{conn: conn}
}

func (r *Repository) Close() error {
	return r.conn.Close()
}

func applyMigrations(db *sql.DB, conf *conf.DBConfig) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return err
	}

	path, _ := filepath.Abs("internal/repo/db/migration")
	path = filepath.ToSlash(path)

	m, err := migrate.NewWithDatabaseInstance("file://"+path, conf.Database, driver)
	if err != nil {
		return err
	}

	if err = m.Up(); err != nil && errors.Is(err, migrate.ErrNoChange) {
		zap.L().Info("No migrations to apply")
		return nil
	} else if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}

	zap.L().Info("Applied migrations")
	return nil
}

func (r *Repository) GetUserByUsername(ctx context.Context, name string) (*model.User, error) {
	const op = "store.GetUserByUsername.repo"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	defer span.Finish()

	res := &model.User{}
	err := r.conn.QueryRow(userGet, name).Scan(&res.ID, &res.Username, &res.Password, &res.Balance)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, repo.ErrNotFound
	} else if err != nil {
		return nil, err
	}

	return res, nil
}

func (r *Repository) CreateUser(ctx context.Context, username, pswd string) (uuid.UUID, error) {
	const op = "store.CreateUser.repo"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	defer span.Finish()

	var id uuid.UUID
	err := r.conn.QueryRow(userCreate, username, pswd, conf.DefaultBalance).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique constraint") {
			return uuid.Nil, repo.ErrAlreadyExists
		}
		return uuid.Nil, err
	}

	return id, nil
}

func (r *Repository) GetInfo(ctx context.Context, uid uuid.UUID) (*model.InfoResponse, error) {
	const op = "store.GetInfo.repo"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	defer span.Finish()

	res := &model.InfoResponse{}
	err := r.conn.QueryRow(getInfo)
	if err != nil {
		if strings.Contains(err.Error(), "unique constraint") {
			return nil, repo.ErrAlreadyExists
		}
		return nil, err
	}

	return id, nil
}

func (r *Repository) SendCoin(ctx context.Context, req *model.SendCoinRequest) error {
	const op = "store.SendCoin.repo"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	defer span.Finish()
}

func (r *Repository) BuyItem(ctx context.Context, item string) error {
	const op = "store.BuyItem.repo"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	defer span.Finish()
}
