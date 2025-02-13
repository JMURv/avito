package ctrl

import (
	"context"
	"errors"
	"github.com/JMURv/avito/internal/auth"
	"github.com/JMURv/avito/internal/repo"
	"github.com/JMURv/avito/pkg/model"
	"github.com/google/uuid"
	"github.com/opentracing/opentracing-go"
	"go.uber.org/zap"
	"io"
	"time"
)

type AppRepo interface {
	GetUserByUsername(ctx context.Context, name string) (*model.User, error)
	CreateUser(ctx context.Context, username, pswd string) (uuid.UUID, error)
	GetInfo(ctx context.Context, uid uuid.UUID) (*model.InfoResponse, error)
	SendCoin(ctx context.Context, uid uuid.UUID, req *model.SendCoinRequest) error
	BuyItem(ctx context.Context, uid uuid.UUID, item string) error
}

type AppCtrl interface {
	AuthUser(ctx context.Context, req *model.User) (string, error)
	GetInfo(ctx context.Context, uid uuid.UUID) (*model.InfoResponse, error)
	SendCoin(ctx context.Context, uid uuid.UUID, req *model.SendCoinRequest) error
	BuyItem(ctx context.Context, uid uuid.UUID, item string) error
}

type CacheService interface {
	io.Closer
	GetToStruct(ctx context.Context, key string, dest any) error
	Set(ctx context.Context, t time.Duration, key string, val any) error
	Delete(ctx context.Context, key string) error
	InvalidateKeysByPattern(ctx context.Context, pattern string)
}

type Controller struct {
	repo  AppRepo
	cache CacheService
	auth  auth.AuthService
}

func New(auth auth.AuthService, repo AppRepo, cache CacheService) *Controller {
	return &Controller{
		auth:  auth,
		repo:  repo,
		cache: cache,
	}
}

func (c *Controller) AuthUser(ctx context.Context, req *model.User) (string, error) {
	const op = "store.AuthUser.ctrl"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	ctx = opentracing.ContextWithSpan(ctx, span)
	defer span.Finish()

	res, err := c.repo.GetUserByUsername(ctx, req.Username)
	if err != nil && errors.Is(err, repo.ErrNotFound) {
		zap.L().Info(
			"user not found, creating...",
			zap.String("username", req.Username),
		)

		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			return "", err
		}

		uid, err := c.repo.CreateUser(ctx, req.Username, hash)
		if err != nil && errors.Is(err, repo.ErrAlreadyExists) {
			return "", ErrAlreadyExists
		} else if err != nil {
			return "", err
		}

		token, err := c.auth.NewToken(uid)
		if err != nil {
			return "", err
		}
		return token, nil
	} else if err != nil {
		return "", err
	}

	if err = c.auth.ComparePasswords([]byte(req.Password), []byte(res.Password)); err != nil {
		return "", err
	}

	token, err := c.auth.NewToken(req.ID)
	if err != nil {
		return "", err
	}
	return token, nil
}

func (c *Controller) GetInfo(ctx context.Context, uid uuid.UUID) (*model.InfoResponse, error) {
	const op = "store.GetInfo.ctrl"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	ctx = opentracing.ContextWithSpan(ctx, span)
	defer span.Finish()

	res, err := c.repo.GetInfo(ctx, uid)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *Controller) SendCoin(ctx context.Context, uid uuid.UUID, req *model.SendCoinRequest) error {
	const op = "store.SendCoin.ctrl"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	ctx = opentracing.ContextWithSpan(ctx, span)
	defer span.Finish()

	err := c.repo.SendCoin(ctx, uid, req)
	if err != nil {
		return err
	}

	return nil
}

func (c *Controller) BuyItem(ctx context.Context, uid uuid.UUID, item string) error {
	const op = "store.BuyItem.ctrl"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	ctx = opentracing.ContextWithSpan(ctx, span)
	defer span.Finish()

	err := c.repo.BuyItem(ctx, uid, item)
	if err != nil {
		return err
	}

	return nil
}
