package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	conf "github.com/JMURv/avito/internal/config"
	"github.com/JMURv/avito/internal/dto"
	"github.com/JMURv/avito/internal/model"
	"github.com/JMURv/avito/internal/repo"
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

	rootDir, err := findRootDir()
	if err != nil {
		return err
	}

	path := filepath.ToSlash(
		filepath.Join(rootDir, "internal", "repo", "db", "migration"),
	)

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
	err := r.conn.QueryRow(getUser, name).Scan(&res.ID, &res.Username, &res.Password, &res.Balance)
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
	err := r.conn.QueryRow(createUser, username, pswd, conf.DefaultBalance).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "unique constraint") {
			return uuid.Nil, repo.ErrAlreadyExists
		}
		return uuid.Nil, err
	}

	return id, nil
}

func (r *Repository) GetInfo(ctx context.Context, uid uuid.UUID, page, size int) (*dto.InfoResponse, error) {
	const op = "store.GetInfo.repo"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	defer span.Finish()

	res := &dto.InfoResponse{}
	err := r.conn.QueryRow(getUserBalance, uid).Scan(&res.Coins)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return nil, repo.ErrNotFound
	} else if err != nil {
		return nil, err
	}

	rows, err := r.conn.Query(getUserInventory, uid, size, (page-1)*size)
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		if err := rows.Close(); err != nil {
			zap.L().Error("Error while closing rows", zap.Error(err))
		}
	}(rows)

	invItms := make([]dto.Inventory, 0, size)
	for rows.Next() {
		i := dto.Inventory{}
		if err = rows.Scan(&i.Quantity, &i.Type); err != nil {
			return nil, err
		}
		invItms = append(invItms, i)
	}

	rows, err = r.conn.Query(getUserTransactions, uid, size, (page-1)*size)
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		if err := rows.Close(); err != nil {
			zap.L().Error("Error while closing rows", zap.Error(err))
		}
	}(rows)

	recv := make([]dto.ReceivedCoins, 0, size)
	sent := make([]dto.SentCoins, 0, size)
	for rows.Next() {
		var amount int
		var from, to uuid.UUID
		var fromName, toName string

		if err = rows.Scan(&from, &fromName, &to, &toName, &amount); err != nil {
			return nil, err
		}

		if uid == to {
			recv = append(
				recv, dto.ReceivedCoins{
					FromUser: fromName,
					Amount:   amount,
				},
			)
		} else {
			sent = append(
				sent, dto.SentCoins{
					ToUser: toName,
					Amount: amount,
				},
			)
		}
	}

	res.Inventory = invItms
	res.CoinHistory.Sent = sent
	res.CoinHistory.Received = recv
	return res, nil
}

func (r *Repository) SendCoin(ctx context.Context, uid uuid.UUID, req *dto.SendCoinRequest) error {
	const op = "store.SendCoin.repo"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	defer span.Finish()

	tx, err := r.conn.BeginTx(
		ctx, &sql.TxOptions{
			Isolation: sql.LevelSerializable,
		},
	)
	if err != nil {
		return err
	}
	defer func() {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			zap.L().Error(
				"Error while transaction rollback",
				zap.Error(err), zap.Error(rbErr),
				zap.String("uid", uid.String()),
				zap.Any("req", req),
			)
		}
	}()

	res, err := tx.Exec(sendCoinFrom, req.Amount, uid)
	if err != nil {
		return err
	}

	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if aff == 0 {
		return repo.ErrNotFound
	}

	res, err = tx.Exec(sendCoinTo, req.Amount, req.ToUser)
	if err != nil {
		return err
	}

	aff, err = res.RowsAffected()
	if err != nil {
		return err
	}

	if aff == 0 {
		return repo.ErrNotFound
	}

	res, err = tx.Exec(createTransaction, uid, req.ToUser, req.Amount)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (r *Repository) BuyItem(ctx context.Context, uid uuid.UUID, item string) error {
	const op = "store.BuyItem.repo"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	defer span.Finish()

	tx, err := r.conn.BeginTx(
		ctx, &sql.TxOptions{
			Isolation: sql.LevelSerializable,
		},
	)
	if err != nil {
		return err
	}
	defer func() {
		if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			zap.L().Error(
				"Error while transaction rollback",
				zap.Error(err),
				zap.String("uid", uid.String()),
				zap.Any("item", item),
			)
		}
	}()

	itemObj := model.Item{}
	err = tx.QueryRow(getItem, item).Scan(
		&itemObj.ID, &itemObj.Name, &itemObj.Price,
	)
	if err != nil && errors.Is(err, sql.ErrNoRows) {
		return repo.ErrNotFound
	} else if err != nil {
		return err
	}

	res, err := tx.Exec(sendCoinFrom, itemObj.Price, uid)
	if err != nil {
		return err
	}

	aff, err := res.RowsAffected()
	if err != nil {
		return err
	}

	if aff == 0 {
		return repo.ErrNotFound
	}

	res, err = tx.Exec(upsertInventory, uid, itemObj.ID)
	if err != nil {
		return err
	}

	return tx.Commit()
}
