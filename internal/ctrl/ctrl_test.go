package ctrl

import (
	"context"
	"errors"
	"github.com/JMURv/avito/internal/config"
	"github.com/JMURv/avito/internal/dto"
	"github.com/JMURv/avito/internal/model"
	"github.com/JMURv/avito/internal/repo"
	"github.com/JMURv/avito/tests/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"testing"
)

func TestController_AuthUser(t *testing.T) {
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mrepo := mocks.NewMockAppRepo(mock)
	ctrl := New(mau, mrepo)

	uid := uuid.New()
	token := uuid.NewString()
	testErr := errors.New("test-err")
	hash := uuid.NewString()
	req := &model.User{
		ID:       uuid.New(),
		Username: "username",
		Password: "password",
	}

	tests := []struct {
		name         string
		req          *model.User
		mockExpect   func()
		expectedResp func(*testing.T, any, error)
	}{
		{
			name: "HashErr",
			req:  req,
			mockExpect: func() {
				mrepo.EXPECT().GetUserByUsername(
					gomock.Any(),
					req.Username,
				).Return(nil, repo.ErrNotFound).Times(1)

				mau.EXPECT().HashPassword(
					req.Password,
				).Return("", testErr).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "CreateUserErr",
			req:  req,
			mockExpect: func() {
				mrepo.EXPECT().GetUserByUsername(
					gomock.Any(),
					req.Username,
				).Return(nil, repo.ErrNotFound).Times(1)

				mau.EXPECT().HashPassword(
					req.Password,
				).Return(hash, nil).Times(1)

				mrepo.EXPECT().CreateUser(
					gomock.Any(),
					req.Username,
					hash,
				).Return(uuid.Nil, testErr).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "NewTokenErr",
			req:  req,
			mockExpect: func() {
				mrepo.EXPECT().GetUserByUsername(
					gomock.Any(),
					req.Username,
				).Return(nil, repo.ErrNotFound).Times(1)

				mau.EXPECT().HashPassword(
					req.Password,
				).Return(hash, nil).Times(1)

				mrepo.EXPECT().CreateUser(
					gomock.Any(),
					req.Username,
					hash,
				).Return(uid, nil).Times(1)

				mau.EXPECT().NewToken(
					uid,
				).Return("", testErr).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "Success -- new user",
			req:  req,
			mockExpect: func() {
				mrepo.EXPECT().GetUserByUsername(
					gomock.Any(),
					req.Username,
				).Return(nil, repo.ErrNotFound).Times(1)

				mau.EXPECT().HashPassword(
					req.Password,
				).Return(hash, nil).Times(1)

				mrepo.EXPECT().CreateUser(
					gomock.Any(),
					req.Username,
					hash,
				).Return(uid, nil).Times(1)

				mau.EXPECT().NewToken(
					uid,
				).Return(token, nil).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				require.NoError(t, err)
				assert.NotNil(t, res)
				assert.Equal(t, token, res.(*dto.TokenResponse).Token)
			},
		},
		{
			name: "GetUserByUsername -- Error",
			req:  req,
			mockExpect: func() {
				mrepo.EXPECT().GetUserByUsername(
					gomock.Any(),
					req.Username,
				).Return(nil, testErr).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "ComparePasswordErr",
			req:  req,
			mockExpect: func() {
				mrepo.EXPECT().GetUserByUsername(
					gomock.Any(),
					req.Username,
				).Return(req, nil).Times(1)

				mau.EXPECT().ComparePasswords(
					[]byte(req.Password),
					[]byte(req.Password),
				).Return(testErr).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "NewTokenErr",
			req:  req,
			mockExpect: func() {
				mrepo.EXPECT().GetUserByUsername(
					gomock.Any(),
					req.Username,
				).Return(req, nil).Times(1)

				mau.EXPECT().ComparePasswords(
					[]byte(req.Password),
					[]byte(req.Password),
				).Return(nil).Times(1)

				mau.EXPECT().NewToken(
					req.ID,
				).Return("", testErr).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "Success -- existing user",
			req:  req,
			mockExpect: func() {
				mrepo.EXPECT().GetUserByUsername(
					gomock.Any(),
					req.Username,
				).Return(req, nil).Times(1)

				mau.EXPECT().ComparePasswords(
					[]byte(req.Password),
					[]byte(req.Password),
				).Return(nil).Times(1)

				mau.EXPECT().NewToken(
					req.ID,
				).Return(token, nil).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				require.NoError(t, err)
				assert.NotNil(t, res)
				assert.Equal(t, token, res.(*dto.TokenResponse).Token)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				res, err := ctrl.AuthUser(context.Background(), tt.req)
				tt.expectedResp(t, res, err)
			},
		)
	}
}

func TestController_GetInfo(t *testing.T) {
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mrepo := mocks.NewMockAppRepo(mock)
	ctrl := New(mau, mrepo)

	uid := uuid.New()
	testErr := errors.New("test error")
	successRes := &dto.InfoResponse{Coins: 1000}

	tests := []struct {
		name         string
		mockExpect   func()
		expectedResp func(*testing.T, any, error)
	}{
		{
			name: "ErrNotFound",
			mockExpect: func() {
				mrepo.EXPECT().GetInfo(
					gomock.Any(),
					uid,
					config.DefaultPage,
					config.DefaultSize,
				).Return(nil, repo.ErrNotFound).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, ErrNotFound, err)
			},
		},
		{
			name: "ErrInternal",
			mockExpect: func() {
				mrepo.EXPECT().GetInfo(
					gomock.Any(),
					uid,
					config.DefaultPage,
					config.DefaultSize,
				).Return(nil, testErr).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "Success",
			mockExpect: func() {
				mrepo.EXPECT().GetInfo(
					gomock.Any(),
					uid,
					config.DefaultPage,
					config.DefaultSize,
				).Return(successRes, nil).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				require.NoError(t, err)
				assert.NotNil(t, res)
				assert.Equal(t, successRes.Coins, res.(*dto.InfoResponse).Coins)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				res, err := ctrl.GetInfo(context.Background(), uid, config.DefaultPage, config.DefaultSize)
				tt.expectedResp(t, res, err)
			},
		)
	}
}

func TestController_SendCoin(t *testing.T) {
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mrepo := mocks.NewMockAppRepo(mock)
	ctrl := New(mau, mrepo)

	uid := uuid.New()
	testErr := errors.New("test error")
	req := &dto.SendCoinRequest{ToUser: "test", Amount: 1000}

	tests := []struct {
		name         string
		mockExpect   func()
		expectedResp func(*testing.T, any, error)
	}{
		{
			name: "ErrNotFound",
			mockExpect: func() {
				mrepo.EXPECT().SendCoin(
					gomock.Any(),
					uid,
					req,
				).Return(repo.ErrNotFound).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, ErrNotFound, err)
			},
		},
		{
			name: "ErrInternal",
			mockExpect: func() {
				mrepo.EXPECT().SendCoin(
					gomock.Any(),
					uid,
					req,
				).Return(testErr).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "Success",
			mockExpect: func() {
				mrepo.EXPECT().SendCoin(
					gomock.Any(),
					uid,
					req,
				).Return(nil).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				require.NoError(t, err)
				assert.Nil(t, res)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				err := ctrl.SendCoin(context.Background(), uid, req)
				tt.expectedResp(t, nil, err)
			},
		)
	}
}

func TestController_BuyItem(t *testing.T) {
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mrepo := mocks.NewMockAppRepo(mock)
	ctrl := New(mau, mrepo)

	uid := uuid.New()
	testErr := errors.New("test error")
	item := "itemname"

	tests := []struct {
		name         string
		mockExpect   func()
		expectedResp func(*testing.T, any, error)
	}{
		{
			name: "ErrNotFound",
			mockExpect: func() {
				mrepo.EXPECT().BuyItem(
					gomock.Any(),
					uid,
					item,
				).Return(repo.ErrNotFound).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, ErrNotFound, err)
			},
		},
		{
			name: "ErrInternal",
			mockExpect: func() {
				mrepo.EXPECT().BuyItem(
					gomock.Any(),
					uid,
					item,
				).Return(testErr).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, res)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "Success",
			mockExpect: func() {
				mrepo.EXPECT().BuyItem(
					gomock.Any(),
					uid,
					item,
				).Return(nil).Times(1)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				require.NoError(t, err)
				assert.Nil(t, res)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				err := ctrl.BuyItem(context.Background(), uid, item)
				tt.expectedResp(t, nil, err)
			},
		)
	}
}
