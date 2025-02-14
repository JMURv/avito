package ctrl

import (
	"context"
	"errors"
	"github.com/JMURv/avito/internal/auth"
	"github.com/JMURv/avito/internal/dto"
	"github.com/JMURv/avito/internal/model"
	"github.com/JMURv/avito/internal/repo"
	"github.com/google/uuid"
	"github.com/opentracing/opentracing-go"
	"go.uber.org/zap"
)

type AppRepo interface {
	GetUserByUsername(ctx context.Context, name string) (*model.User, error)
	CreateUser(ctx context.Context, username, pswd string) (uuid.UUID, error)
	GetInfo(ctx context.Context, uid uuid.UUID) (*dto.InfoResponse, error)
	SendCoin(ctx context.Context, uid uuid.UUID, req *dto.SendCoinRequest) error
	BuyItem(ctx context.Context, uid uuid.UUID, item string) error
}

type AppCtrl interface {
	AuthUser(ctx context.Context, req *model.User) (*dto.TokenResponse, error)
	GetInfo(ctx context.Context, uid uuid.UUID) (*dto.InfoResponse, error)
	SendCoin(ctx context.Context, uid uuid.UUID, req *dto.SendCoinRequest) error
	BuyItem(ctx context.Context, uid uuid.UUID, item string) error
}

type Controller struct {
	repo AppRepo
	auth auth.AuthService
}

func New(auth auth.AuthService, repo AppRepo) *Controller {
	return &Controller{
		auth: auth,
		repo: repo,
	}
}

func (c *Controller) AuthUser(ctx context.Context, req *model.User) (*dto.TokenResponse, error) {
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

		hash, err := c.auth.HashPassword(req.Password)
		if err != nil {
			return nil, err
		}

		uid, err := c.repo.CreateUser(ctx, req.Username, hash)
		if err != nil {
			return nil, err
		}

		token, err := c.auth.NewToken(uid)
		if err != nil {
			return nil, err
		}
		return &dto.TokenResponse{Token: token}, nil
	} else if err != nil {
		return nil, err
	}

	if err = c.auth.ComparePasswords([]byte(req.Password), []byte(res.Password)); err != nil {
		return nil, err
	}

	token, err := c.auth.NewToken(req.ID)
	if err != nil {
		return nil, err
	}
	return &dto.TokenResponse{Token: token}, nil
}

func (c *Controller) GetInfo(ctx context.Context, uid uuid.UUID) (*dto.InfoResponse, error) {
	const op = "store.GetInfo.ctrl"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	ctx = opentracing.ContextWithSpan(ctx, span)
	defer span.Finish()

	res, err := c.repo.GetInfo(ctx, uid)
	if err != nil && errors.Is(err, repo.ErrNotFound) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, err
	}

	return res, nil
}

func (c *Controller) SendCoin(ctx context.Context, uid uuid.UUID, req *dto.SendCoinRequest) error {
	const op = "store.SendCoin.ctrl"
	span, _ := opentracing.StartSpanFromContext(ctx, op)
	ctx = opentracing.ContextWithSpan(ctx, span)
	defer span.Finish()

	err := c.repo.SendCoin(ctx, uid, req)
	if err != nil && errors.Is(err, repo.ErrNotFound) {
		return ErrNotFound
	} else if err != nil {
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
	if err != nil && errors.Is(err, repo.ErrNotFound) {
		return ErrNotFound
	} else if err != nil {
		return err
	}

	return nil
}
