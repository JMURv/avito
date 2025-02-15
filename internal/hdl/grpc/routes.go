package grpc

import (
	"context"
	"errors"
	"github.com/JMURv/avito/api/grpc/gen"
	"github.com/JMURv/avito/internal/auth"
	"github.com/JMURv/avito/internal/config"
	"github.com/JMURv/avito/internal/ctrl"
	"github.com/JMURv/avito/internal/dto"
	mappers "github.com/JMURv/avito/internal/dto/mapper"
	"github.com/JMURv/avito/internal/hdl"
	"github.com/JMURv/avito/internal/hdl/validation"
	"github.com/JMURv/avito/internal/model"
	metrics "github.com/JMURv/avito/internal/observability/metrics/prometheus"
	"github.com/google/uuid"
	"github.com/opentracing/opentracing-go"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"
)

func (h *Handler) Auth(ctx context.Context, req *gen.AuthReq) (*gen.TokenRes, error) {
	s, c := time.Now(), codes.OK
	const op = "store.auth.hdl"
	span := opentracing.GlobalTracer().StartSpan(op)
	ctx = opentracing.ContextWithSpan(ctx, span)
	defer func() {
		span.Finish()
		metrics.ObserveRequest(time.Since(s), int(c), op)
	}()

	if req == nil || req.Username == "" || req.Password == "" {
		c = codes.InvalidArgument
		zap.L().Debug("failed to decode request", zap.String("op", op))
		return nil, status.Errorf(c, hdl.ErrDecodeRequest.Error())
	}

	usr := &model.User{
		Username: req.Username,
		Password: req.Password,
	}

	if err := validation.AuthReq(usr); err != nil {
		c = codes.InvalidArgument
		zap.L().Debug(
			"failed to validate auth request",
			zap.String("op", op), zap.Error(err),
		)
		return nil, status.Error(c, err.Error())
	}

	res, err := h.ctrl.AuthUser(ctx, usr)
	if err != nil && errors.Is(err, auth.ErrInvalidCredentials) {
		c = codes.Unauthenticated
		return nil, status.Error(c, err.Error())
	} else if err != nil {
		c = codes.Internal
		zap.L().Debug(
			hdl.ErrInternal.Error(),
			zap.String("op", op), zap.Error(err),
		)
		return nil, status.Error(c, hdl.ErrInternal.Error())
	}

	return &gen.TokenRes{
		Token: res.Token,
	}, nil
}

func (h *Handler) GetInfo(ctx context.Context, req *gen.PageAndSize) (*gen.InfoResponse, error) {
	s, c := time.Now(), codes.OK
	const op = "store.GetInfo.hdl"
	span := opentracing.GlobalTracer().StartSpan(op)
	ctx = opentracing.ContextWithSpan(ctx, span)
	defer func() {
		span.Finish()
		metrics.ObserveRequest(time.Since(s), int(c), op)
	}()

	if req == nil {
		c = codes.InvalidArgument
		zap.L().Debug("failed to decode request", zap.String("op", op))
		return nil, status.Errorf(c, hdl.ErrDecodeRequest.Error())
	}

	uidStr, ok := ctx.Value("uid").(string)
	if !ok {
		c = codes.InvalidArgument
		zap.L().Error(
			hdl.ErrFailedToGetUUID.Error(),
			zap.String("op", op), zap.Any("uid", ctx.Value("uid")),
		)
		return nil, status.Error(c, hdl.ErrDecodeRequest.Error())
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		c = codes.InvalidArgument
		zap.L().Error(
			hdl.ErrFailedToParseUUID.Error(),
			zap.String("op", op), zap.String("uid", uidStr),
		)
		return nil, status.Error(c, hdl.ErrDecodeRequest.Error())
	}

	if req.Page <= 0 {
		req.Page = config.DefaultPage
	}

	if req.Size <= 0 {
		req.Size = config.DefaultSize
	}

	res, err := h.ctrl.GetInfo(ctx, uid, int(req.Page), int(req.Size))
	if err != nil {
		c = codes.Internal
		zap.L().Debug(
			hdl.ErrInternal.Error(),
			zap.String("op", op), zap.Error(err),
		)
		return nil, status.Error(c, hdl.ErrInternal.Error())
	}

	return mappers.InfoToProto(res), nil
}

func (h *Handler) SendCoin(ctx context.Context, req *gen.SendCoinRequest) (*gen.Empty, error) {
	s, c := time.Now(), codes.OK
	const op = "store.SendCoin.hdl"
	span := opentracing.GlobalTracer().StartSpan(op)
	ctx = opentracing.ContextWithSpan(ctx, span)
	defer func() {
		span.Finish()
		metrics.ObserveRequest(time.Since(s), int(c), op)
	}()

	if req == nil || req.ToUser == "" || req.Amount == 0 {
		c = codes.InvalidArgument
		zap.L().Debug("failed to decode request", zap.String("op", op))
		return nil, status.Errorf(c, hdl.ErrDecodeRequest.Error())
	}

	uidStr, ok := ctx.Value("uid").(string)
	if !ok {
		c = codes.InvalidArgument
		zap.L().Error(
			hdl.ErrFailedToGetUUID.Error(),
			zap.String("op", op), zap.Any("uid", ctx.Value("uid")),
		)
		return nil, status.Error(c, hdl.ErrDecodeRequest.Error())
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		c = codes.InvalidArgument
		zap.L().Error(
			hdl.ErrFailedToParseUUID.Error(),
			zap.String("op", op), zap.String("uid", uidStr),
		)
		return nil, status.Error(c, hdl.ErrDecodeRequest.Error())
	}

	err = h.ctrl.SendCoin(
		ctx, uid, &dto.SendCoinRequest{
			ToUser: req.ToUser,
			Amount: int(req.Amount),
		},
	)
	if err != nil && errors.Is(err, ctrl.ErrNotFound) {
		c = codes.NotFound
		return nil, status.Error(c, err.Error())
	} else if err != nil {
		c = codes.Internal
		zap.L().Debug(
			hdl.ErrInternal.Error(),
			zap.String("op", op), zap.Error(err),
		)
		return nil, status.Error(c, hdl.ErrInternal.Error())
	}

	return &gen.Empty{}, nil
}

func (h *Handler) BuyItem(ctx context.Context, req *gen.BuyItemRequest) (*gen.Empty, error) {
	s, c := time.Now(), codes.OK
	const op = "store.BuyItem.hdl"
	span := opentracing.GlobalTracer().StartSpan(op)
	ctx = opentracing.ContextWithSpan(ctx, span)
	defer func() {
		span.Finish()
		metrics.ObserveRequest(time.Since(s), int(c), op)
	}()

	if req == nil || req.Type == "" {
		c = codes.InvalidArgument
		zap.L().Debug("failed to decode request", zap.String("op", op))
		return nil, status.Errorf(c, hdl.ErrDecodeRequest.Error())
	}

	uidStr, ok := ctx.Value("uid").(string)
	if !ok {
		c = codes.InvalidArgument
		zap.L().Error(
			hdl.ErrFailedToGetUUID.Error(),
			zap.String("op", op), zap.Any("uid", ctx.Value("uid")),
		)
		return nil, status.Error(c, hdl.ErrDecodeRequest.Error())
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		c = codes.InvalidArgument
		zap.L().Error(
			hdl.ErrFailedToParseUUID.Error(),
			zap.String("op", op), zap.String("uid", uidStr),
		)
		return nil, status.Error(c, hdl.ErrDecodeRequest.Error())
	}

	err = h.ctrl.BuyItem(ctx, uid, req.Type)
	if err != nil && errors.Is(err, ctrl.ErrNotFound) {
		c = codes.NotFound
		return nil, status.Error(c, err.Error())
	} else if err != nil {
		c = codes.Internal
		zap.L().Debug(
			hdl.ErrInternal.Error(),
			zap.String("op", op), zap.Error(err),
		)
		return nil, status.Error(c, hdl.ErrInternal.Error())
	}

	return &gen.Empty{}, nil
}
