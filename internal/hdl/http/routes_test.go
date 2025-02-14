package http

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/JMURv/avito/internal/auth"
	"github.com/JMURv/avito/internal/dto"
	"github.com/JMURv/avito/internal/hdl"
	"github.com/JMURv/avito/internal/hdl/http/utils"
	"github.com/JMURv/avito/internal/hdl/validation"
	"github.com/JMURv/avito/internal/model"
	"github.com/JMURv/avito/tests/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler_Auth(t *testing.T) {
	const uri = "/api/auth"
	const failPass = "1234"
	const successPass = "123456"
	const successUsername = "username"
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mctrl := mocks.NewMockAppCtrl(mock)
	h := New(mau, mctrl)

	token := uuid.NewString()

	tests := []struct {
		name         string
		method       string
		url          string
		body         any
		resType      any
		status       int
		mockExpect   func()
		expectedResp func(*testing.T, any)
	}{
		{
			name:       "InvalidMethod",
			method:     http.MethodGet,
			url:        uri,
			body:       nil,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusMethodNotAllowed,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, errResp.Errors, ErrMethodNotAllowed.Error())
			},
		},
		{
			name:   "ErrDecodeRequest",
			method: http.MethodPost,
			url:    uri,
			body: map[string]any{
				"username": 0,
				"password": successPass,
			},
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrDecodeRequest.Error(), errResp.Errors)
			},
		},
		{
			name:   "ValidationErr -- UsernameIsRequired",
			method: http.MethodPost,
			url:    uri,
			body: map[string]string{
				"username": "",
				"password": successPass,
			},
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, validation.UsernameIsRequired.Error(), errResp.Errors)
			},
		},
		{
			name:   "ValidationErr -- PasswordIsRequired",
			method: http.MethodPost,
			url:    uri,
			body: map[string]string{
				"username": successUsername,
				"password": "",
			},
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, validation.PasswordIsRequired.Error(), errResp.Errors)
			},
		},
		{
			name:   "ValidationErr -- PasswordIsTooShort",
			method: http.MethodPost,
			url:    uri,
			body: map[string]string{
				"username": successUsername,
				"password": failPass,
			},
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, validation.PasswordIsTooShort.Error(), errResp.Errors)
			},
		},
		{
			name:   "ErrInvalidCredentials",
			method: http.MethodPost,
			url:    uri,
			body: map[string]string{
				"username": successUsername,
				"password": successPass,
			},
			resType: &utils.ErrorResponse{},
			status:  http.StatusUnauthorized,
			mockExpect: func() {
				mctrl.EXPECT().AuthUser(
					gomock.Any(), &model.User{
						Username: successUsername,
						Password: successPass,
					},
				).Return(nil, auth.ErrInvalidCredentials)
			},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, auth.ErrInvalidCredentials.Error(), errResp.Errors)
			},
		},
		{
			name:   "InternalError",
			method: http.MethodPost,
			url:    uri,
			body: map[string]string{
				"username": successUsername,
				"password": successPass,
			},
			resType: &utils.ErrorResponse{},
			status:  http.StatusInternalServerError,
			mockExpect: func() {
				mctrl.EXPECT().AuthUser(
					gomock.Any(), &model.User{
						Username: successUsername,
						Password: successPass,
					},
				).Return(nil, errors.New("test-err"))
			},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrInternal.Error(), errResp.Errors)
			},
		},
		{
			name:   "Success",
			method: http.MethodPost,
			url:    uri,
			body: map[string]string{
				"username": successUsername,
				"password": successPass,
			},
			resType: &dto.TokenResponse{},
			status:  http.StatusOK,
			mockExpect: func() {
				mctrl.EXPECT().AuthUser(
					gomock.Any(), &model.User{
						Username: successUsername,
						Password: successPass,
					},
				).Return(&dto.TokenResponse{Token: token}, nil)
			},
			expectedResp: func(t *testing.T, res any) {
				resp, ok := res.(*dto.TokenResponse)
				require.True(t, ok)
				assert.Equal(t, token, resp.Token)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()

				body, err := json.Marshal(tt.body)
				require.Nil(t, err)

				req := httptest.NewRequest(tt.method, tt.url, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				w := httptest.NewRecorder()
				h.auth(w, req)

				res := tt.resType
				err = json.NewDecoder(w.Result().Body).Decode(res)
				assert.Nil(t, err)

				assert.Equal(t, tt.status, w.Result().StatusCode)
				tt.expectedResp(t, res)
			},
		)
	}
}

func TestHandler_GetInfo(t *testing.T) {
	const uri = "/api/info"
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mctrl := mocks.NewMockAppCtrl(mock)
	h := New(mau, mctrl)

	uid := uuid.NewString()
	successCtx := context.WithValue(context.Background(), "uid", uid)
	failureCtx := context.WithValue(context.Background(), "uid", uid+"1")
	emptyCtx := context.Background()

	successDTO := &dto.InfoResponse{Coins: 1000}

	tests := []struct {
		ctx          context.Context
		name         string
		method       string
		url          string
		body         any
		resType      any
		status       int
		mockExpect   func()
		expectedResp func(*testing.T, any)
	}{
		{
			ctx:        emptyCtx,
			name:       "InvalidMethod",
			method:     http.MethodPost,
			url:        uri,
			body:       nil,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusMethodNotAllowed,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, errResp.Errors, ErrMethodNotAllowed.Error())
			},
		},
		{
			ctx:        emptyCtx,
			name:       "ErrFailedToGetUUID",
			method:     http.MethodGet,
			url:        uri,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrDecodeRequest.Error(), errResp.Errors)
			},
		},
		{
			ctx:        failureCtx,
			name:       "ErrFailedToParseUUID",
			method:     http.MethodGet,
			url:        uri,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrDecodeRequest.Error(), errResp.Errors)
			},
		},
		{
			ctx:     successCtx,
			name:    "InternalError",
			method:  http.MethodGet,
			url:     uri,
			resType: &utils.ErrorResponse{},
			status:  http.StatusInternalServerError,
			mockExpect: func() {
				mctrl.EXPECT().GetInfo(
					gomock.Any(), uuid.MustParse(uid),
				).Return(nil, errors.New("test-err"))
			},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrInternal.Error(), errResp.Errors)
			},
		},
		{
			ctx:     successCtx,
			name:    "Success",
			method:  http.MethodGet,
			url:     uri,
			resType: &dto.InfoResponse{},
			status:  http.StatusOK,
			mockExpect: func() {
				mctrl.EXPECT().GetInfo(
					gomock.Any(), uuid.MustParse(uid),
				).Return(successDTO, nil)
			},
			expectedResp: func(t *testing.T, res any) {
				resp, ok := res.(*dto.InfoResponse)
				require.True(t, ok)
				assert.Equal(t, successDTO.Coins, resp.Coins)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()

				body, err := json.Marshal(tt.body)
				require.Nil(t, err)

				req := httptest.NewRequestWithContext(tt.ctx, tt.method, tt.url, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				w := httptest.NewRecorder()
				h.getInfo(w, req)

				res := tt.resType
				err = json.NewDecoder(w.Result().Body).Decode(res)
				assert.Nil(t, err)

				assert.Equal(t, tt.status, w.Result().StatusCode)
				tt.expectedResp(t, res)
			},
		)
	}
}

func TestHandler_SendCoin(t *testing.T) {
	const uri = "/api/sendCoin"
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mctrl := mocks.NewMockAppCtrl(mock)
	h := New(mau, mctrl)

	uid := uuid.NewString()
	successCtx := context.WithValue(context.Background(), "uid", uid)
	failureCtx := context.WithValue(context.Background(), "uid", uid+"1")
	emptyCtx := context.Background()

	successDTO := &dto.SendCoinRequest{ToUser: "username", Amount: 1000}

	tests := []struct {
		ctx          context.Context
		name         string
		method       string
		url          string
		body         any
		resType      any
		status       int
		mockExpect   func()
		expectedResp func(*testing.T, any)
	}{
		{
			ctx:        emptyCtx,
			name:       "InvalidMethod",
			method:     http.MethodGet,
			url:        uri,
			body:       nil,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusMethodNotAllowed,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, errResp.Errors, ErrMethodNotAllowed.Error())
			},
		},
		{
			ctx:        emptyCtx,
			name:       "ErrFailedToGetUUID",
			method:     http.MethodPost,
			url:        uri,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrDecodeRequest.Error(), errResp.Errors)
			},
		},
		{
			ctx:        failureCtx,
			name:       "ErrFailedToParseUUID",
			method:     http.MethodPost,
			url:        uri,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrDecodeRequest.Error(), errResp.Errors)
			},
		},
		{
			ctx:    successCtx,
			name:   "ErrDecodeRequest",
			method: http.MethodPost,
			url:    uri,
			body: map[string]any{
				"toUser": 0,
				"amount": 1000,
			},
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrDecodeRequest.Error(), errResp.Errors)
			},
		},
		{
			ctx:    successCtx,
			name:   "ValidationErr -- ToUserIsRequired",
			method: http.MethodPost,
			url:    uri,
			body: map[string]any{
				"toUser": "",
				"amount": 1000,
			},
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, validation.ToUserIsRequired.Error(), errResp.Errors)
			},
		},
		{
			ctx:    successCtx,
			name:   "ValidationErr -- AmountIsRequired",
			method: http.MethodPost,
			url:    uri,
			body: map[string]any{
				"toUser": "username",
				"amount": 0,
			},
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, validation.AmountIsRequired.Error(), errResp.Errors)
			},
		},
		{
			ctx:    successCtx,
			name:   "InternalError",
			method: http.MethodPost,
			url:    uri,
			body: map[string]any{
				"toUser": "username",
				"amount": 1000,
			},
			resType: &utils.ErrorResponse{},
			status:  http.StatusInternalServerError,
			mockExpect: func() {
				mctrl.EXPECT().SendCoin(
					gomock.Any(), uuid.MustParse(uid), successDTO,
				).Return(errors.New("test-err"))
			},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrInternal.Error(), errResp.Errors)
			},
		},
		{
			ctx:    successCtx,
			name:   "Success",
			method: http.MethodPost,
			url:    uri,
			body: map[string]any{
				"toUser": "username",
				"amount": 1000,
			},
			resType: &dto.InfoResponse{},
			status:  http.StatusOK,
			mockExpect: func() {
				mctrl.EXPECT().SendCoin(
					gomock.Any(), uuid.MustParse(uid), successDTO,
				).Return(nil)
			},
			expectedResp: func(t *testing.T, res any) {},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()

				body, err := json.Marshal(tt.body)
				require.Nil(t, err)

				req := httptest.NewRequestWithContext(tt.ctx, tt.method, tt.url, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				w := httptest.NewRecorder()
				h.sendCoin(w, req)

				res := tt.resType
				_ = json.NewDecoder(w.Result().Body).Decode(res)

				assert.Equal(t, tt.status, w.Result().StatusCode)
				tt.expectedResp(t, res)
			},
		)
	}
}

func TestHandler_BuyItem(t *testing.T) {
	const uri = "/api/buy/"
	mock := gomock.NewController(t)
	defer mock.Finish()

	mau := mocks.NewMockAuthService(mock)
	mctrl := mocks.NewMockAppCtrl(mock)
	h := New(mau, mctrl)

	uid := uuid.NewString()
	successCtx := context.WithValue(context.Background(), "uid", uid)
	failureCtx := context.WithValue(context.Background(), "uid", uid+"1")
	emptyCtx := context.Background()

	tests := []struct {
		ctx          context.Context
		name         string
		method       string
		url          string
		body         any
		resType      any
		status       int
		mockExpect   func()
		expectedResp func(*testing.T, any)
	}{
		{
			ctx:        emptyCtx,
			name:       "InvalidMethod",
			method:     http.MethodPost,
			url:        uri,
			body:       nil,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusMethodNotAllowed,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, errResp.Errors, ErrMethodNotAllowed.Error())
			},
		},
		{
			ctx:        emptyCtx,
			name:       "ErrFailedToGetUUID",
			method:     http.MethodGet,
			url:        uri,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrDecodeRequest.Error(), errResp.Errors)
			},
		},
		{
			ctx:        failureCtx,
			name:       "ErrFailedToParseUUID",
			method:     http.MethodGet,
			url:        uri,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrDecodeRequest.Error(), errResp.Errors)
			},
		},
		{
			ctx:        successCtx,
			name:       "ErrItemIsRequired",
			method:     http.MethodGet,
			url:        uri,
			resType:    &utils.ErrorResponse{},
			status:     http.StatusBadRequest,
			mockExpect: func() {},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, ErrItemIsRequired.Error(), errResp.Errors)
			},
		},
		{
			ctx:     successCtx,
			name:    "InternalError",
			method:  http.MethodGet,
			url:     uri + "item",
			resType: &utils.ErrorResponse{},
			status:  http.StatusInternalServerError,
			mockExpect: func() {
				mctrl.EXPECT().BuyItem(
					gomock.Any(), uuid.MustParse(uid), "item",
				).Return(errors.New("test-err"))
			},
			expectedResp: func(t *testing.T, res any) {
				errResp, ok := res.(*utils.ErrorResponse)
				require.True(t, ok)
				assert.Equal(t, hdl.ErrInternal.Error(), errResp.Errors)
			},
		},
		{
			ctx:     successCtx,
			name:    "Success",
			method:  http.MethodGet,
			url:     uri + "item",
			resType: &dto.InfoResponse{},
			status:  http.StatusOK,
			mockExpect: func() {
				mctrl.EXPECT().BuyItem(
					gomock.Any(), uuid.MustParse(uid), "item",
				).Return(nil)
			},
			expectedResp: func(t *testing.T, res any) {},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()

				body, err := json.Marshal(tt.body)
				require.Nil(t, err)

				req := httptest.NewRequestWithContext(tt.ctx, tt.method, tt.url, bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")

				w := httptest.NewRecorder()
				h.buyItem(w, req)

				res := tt.resType
				_ = json.NewDecoder(w.Result().Body).Decode(res)

				assert.Equal(t, tt.status, w.Result().StatusCode)
				tt.expectedResp(t, res)
			},
		)
	}
}
