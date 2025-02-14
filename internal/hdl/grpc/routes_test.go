package grpc

import (
	"context"
	"errors"
	"github.com/JMURv/avito/api/grpc/gen"
	"github.com/JMURv/avito/internal/auth"
	"github.com/JMURv/avito/internal/ctrl"
	"github.com/JMURv/avito/internal/dto"
	mappers "github.com/JMURv/avito/internal/dto/mapper"
	"github.com/JMURv/avito/tests/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestHandler_Auth(t *testing.T) {
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mctrl := mocks.NewMockAppCtrl(mock)
	h := New(mau, "name", mctrl)

	ctx := context.Background()
	token := uuid.NewString()

	tests := []struct {
		name         string
		req          *gen.AuthReq
		mockExpect   func()
		expectedResp func(*testing.T, *gen.TokenRes, error)
	}{
		{
			name: "Invalid request",
			req: &gen.AuthReq{
				Username: "",
				Password: "",
			},
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.TokenRes, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			name: "Validation Error -- UsernameIsRequired",
			req: &gen.AuthReq{
				Username: "",
				Password: "password",
			},
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.TokenRes, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			name: "Validation Error -- PasswordIsRequired",
			req: &gen.AuthReq{
				Username: "username",
				Password: "",
			},
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.TokenRes, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			name: "Validation Error -- PasswordIsTooShort",
			req: &gen.AuthReq{
				Username: "username",
				Password: "1234",
			},
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.TokenRes, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			name: "ErrInvalidCredentials",
			req: &gen.AuthReq{
				Username: "username",
				Password: "password",
			},
			mockExpect: func() {
				mctrl.EXPECT().AuthUser(gomock.Any(), gomock.Any()).Return(
					nil, auth.ErrInvalidCredentials,
				).Times(1)
			},
			expectedResp: func(t *testing.T, res *gen.TokenRes, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.Unauthenticated, status.Code(err))
			},
		},
		{
			name: "ErrInternal",
			req: &gen.AuthReq{
				Username: "username",
				Password: "password",
			},
			mockExpect: func() {
				mctrl.EXPECT().AuthUser(gomock.Any(), gomock.Any()).Return(
					nil, errors.New("test-err"),
				).Times(1)
			},
			expectedResp: func(t *testing.T, res *gen.TokenRes, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.Internal, status.Code(err))
			},
		},
		{
			name: "Success",
			req: &gen.AuthReq{
				Username: "username",
				Password: "password",
			},
			mockExpect: func() {
				mctrl.EXPECT().AuthUser(gomock.Any(), gomock.Any()).Return(
					&dto.TokenResponse{Token: token}, nil,
				).Times(1)
			},
			expectedResp: func(t *testing.T, res *gen.TokenRes, err error) {
				assert.Equal(
					t, &gen.TokenRes{
						Token: token,
					}, res,
				)
				assert.Equal(t, codes.OK, status.Code(err))
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				res, err := h.Auth(ctx, tt.req)
				tt.expectedResp(t, res, err)
			},
		)
	}
}

func TestHandler_GetInfo(t *testing.T) {
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mctrl := mocks.NewMockAppCtrl(mock)
	h := New(mau, "name", mctrl)

	uid := uuid.NewString()
	successCtx := context.WithValue(context.Background(), "uid", uid)
	failureCtx := context.WithValue(context.Background(), "uid", uid+"1")
	emptyCtx := context.Background()
	successDTO := &dto.InfoResponse{Coins: 1000}

	tests := []struct {
		ctx          context.Context
		name         string
		req          *gen.Empty
		mockExpect   func()
		expectedResp func(*testing.T, *gen.InfoResponse, error)
	}{
		{
			ctx:        emptyCtx,
			name:       "Invalid request",
			req:        nil,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.InfoResponse, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			ctx:        emptyCtx,
			name:       "ErrFailedToGetUUID",
			req:        &gen.Empty{},
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.InfoResponse, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			ctx:        failureCtx,
			name:       "ErrFailedToParseUUID",
			req:        &gen.Empty{},
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.InfoResponse, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			ctx:  successCtx,
			name: "ErrInternal",
			req:  &gen.Empty{},
			mockExpect: func() {
				mctrl.EXPECT().GetInfo(gomock.Any(), gomock.Any()).Return(nil, errors.New("test-err"))
			},
			expectedResp: func(t *testing.T, res *gen.InfoResponse, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.Internal, status.Code(err))
			},
		},
		{
			ctx:  successCtx,
			name: "Success",
			req:  &gen.Empty{},
			mockExpect: func() {
				mctrl.EXPECT().GetInfo(gomock.Any(), gomock.Any()).Return(
					successDTO, nil,
				).Times(1)
			},
			expectedResp: func(t *testing.T, res *gen.InfoResponse, err error) {
				assert.Equal(t, mappers.InfoToProto(successDTO), res)
				assert.Equal(t, codes.OK, status.Code(err))
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				res, err := h.GetInfo(tt.ctx, tt.req)
				tt.expectedResp(t, res, err)
			},
		)
	}
}

func TestHandler_SendCoin(t *testing.T) {
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mctrl := mocks.NewMockAppCtrl(mock)
	h := New(mau, "name", mctrl)

	uid := uuid.NewString()
	successCtx := context.WithValue(context.Background(), "uid", uid)
	failureCtx := context.WithValue(context.Background(), "uid", uid+"1")
	emptyCtx := context.Background()
	validReq := &gen.SendCoinRequest{
		ToUser: "username",
		Amount: 1000,
	}

	tests := []struct {
		ctx          context.Context
		name         string
		req          *gen.SendCoinRequest
		mockExpect   func()
		expectedResp func(*testing.T, *gen.Empty, error)
	}{
		{
			ctx:        emptyCtx,
			name:       "Invalid request -- nil",
			req:        nil,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.Empty, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			ctx:  emptyCtx,
			name: "Invalid request",
			req: &gen.SendCoinRequest{
				ToUser: "",
				Amount: 0,
			},
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.Empty, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			ctx:        emptyCtx,
			name:       "ErrFailedToGetUUID",
			req:        validReq,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.Empty, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			ctx:        failureCtx,
			name:       "ErrFailedToParseUUID",
			req:        validReq,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res *gen.Empty, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.InvalidArgument, status.Code(err))
			},
		},
		{
			ctx:  successCtx,
			name: "ErrNotFound",
			req:  validReq,
			mockExpect: func() {
				mctrl.EXPECT().SendCoin(gomock.Any(), gomock.Any(), gomock.Any()).Return(ctrl.ErrNotFound)
			},
			expectedResp: func(t *testing.T, res *gen.Empty, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.NotFound, status.Code(err))
			},
		},
		{
			ctx:  successCtx,
			name: "ErrInternal",
			req:  validReq,
			mockExpect: func() {
				mctrl.EXPECT().SendCoin(gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("test-err"))
			},
			expectedResp: func(t *testing.T, res *gen.Empty, err error) {
				assert.Nil(t, res)
				assert.Equal(t, codes.Internal, status.Code(err))
			},
		},
		{
			ctx:  successCtx,
			name: "Success",
			req:  validReq,
			mockExpect: func() {
				mctrl.EXPECT().SendCoin(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil).Times(1)
			},
			expectedResp: func(t *testing.T, res *gen.Empty, err error) {
				assert.Equal(t, codes.OK, status.Code(err))
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				res, err := h.SendCoin(tt.ctx, tt.req)
				tt.expectedResp(t, res, err)
			},
		)
	}
}
