// Code generated by MockGen. DO NOT EDIT.
// Source: ./internal/ctrl/ctrl.go
//
// Generated by this command:
//
//	mockgen -source=./internal/ctrl/ctrl.go -destination=tests/mocks/mock_ctrl.go -package=mocks
//

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	dto "github.com/JMURv/avito/internal/dto"
	model "github.com/JMURv/avito/internal/model"
	uuid "github.com/google/uuid"
	gomock "go.uber.org/mock/gomock"
)

// MockAppRepo is a mock of AppRepo interface.
type MockAppRepo struct {
	ctrl     *gomock.Controller
	recorder *MockAppRepoMockRecorder
	isgomock struct{}
}

// MockAppRepoMockRecorder is the mock recorder for MockAppRepo.
type MockAppRepoMockRecorder struct {
	mock *MockAppRepo
}

// NewMockAppRepo creates a new mock instance.
func NewMockAppRepo(ctrl *gomock.Controller) *MockAppRepo {
	mock := &MockAppRepo{ctrl: ctrl}
	mock.recorder = &MockAppRepoMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAppRepo) EXPECT() *MockAppRepoMockRecorder {
	return m.recorder
}

// BuyItem mocks base method.
func (m *MockAppRepo) BuyItem(ctx context.Context, uid uuid.UUID, item string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BuyItem", ctx, uid, item)
	ret0, _ := ret[0].(error)
	return ret0
}

// BuyItem indicates an expected call of BuyItem.
func (mr *MockAppRepoMockRecorder) BuyItem(ctx, uid, item any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BuyItem", reflect.TypeOf((*MockAppRepo)(nil).BuyItem), ctx, uid, item)
}

// CreateUser mocks base method.
func (m *MockAppRepo) CreateUser(ctx context.Context, username, pswd string) (uuid.UUID, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateUser", ctx, username, pswd)
	ret0, _ := ret[0].(uuid.UUID)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateUser indicates an expected call of CreateUser.
func (mr *MockAppRepoMockRecorder) CreateUser(ctx, username, pswd any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateUser", reflect.TypeOf((*MockAppRepo)(nil).CreateUser), ctx, username, pswd)
}

// GetInfo mocks base method.
func (m *MockAppRepo) GetInfo(ctx context.Context, uid uuid.UUID) (*dto.InfoResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInfo", ctx, uid)
	ret0, _ := ret[0].(*dto.InfoResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInfo indicates an expected call of GetInfo.
func (mr *MockAppRepoMockRecorder) GetInfo(ctx, uid any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInfo", reflect.TypeOf((*MockAppRepo)(nil).GetInfo), ctx, uid)
}

// GetUserByUsername mocks base method.
func (m *MockAppRepo) GetUserByUsername(ctx context.Context, name string) (*model.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserByUsername", ctx, name)
	ret0, _ := ret[0].(*model.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserByUsername indicates an expected call of GetUserByUsername.
func (mr *MockAppRepoMockRecorder) GetUserByUsername(ctx, name any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserByUsername", reflect.TypeOf((*MockAppRepo)(nil).GetUserByUsername), ctx, name)
}

// SendCoin mocks base method.
func (m *MockAppRepo) SendCoin(ctx context.Context, uid uuid.UUID, req *dto.SendCoinRequest) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendCoin", ctx, uid, req)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendCoin indicates an expected call of SendCoin.
func (mr *MockAppRepoMockRecorder) SendCoin(ctx, uid, req any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendCoin", reflect.TypeOf((*MockAppRepo)(nil).SendCoin), ctx, uid, req)
}

// MockAppCtrl is a mock of AppCtrl interface.
type MockAppCtrl struct {
	ctrl     *gomock.Controller
	recorder *MockAppCtrlMockRecorder
	isgomock struct{}
}

// MockAppCtrlMockRecorder is the mock recorder for MockAppCtrl.
type MockAppCtrlMockRecorder struct {
	mock *MockAppCtrl
}

// NewMockAppCtrl creates a new mock instance.
func NewMockAppCtrl(ctrl *gomock.Controller) *MockAppCtrl {
	mock := &MockAppCtrl{ctrl: ctrl}
	mock.recorder = &MockAppCtrlMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAppCtrl) EXPECT() *MockAppCtrlMockRecorder {
	return m.recorder
}

// AuthUser mocks base method.
func (m *MockAppCtrl) AuthUser(ctx context.Context, req *model.User) (*dto.TokenResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthUser", ctx, req)
	ret0, _ := ret[0].(*dto.TokenResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthUser indicates an expected call of AuthUser.
func (mr *MockAppCtrlMockRecorder) AuthUser(ctx, req any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthUser", reflect.TypeOf((*MockAppCtrl)(nil).AuthUser), ctx, req)
}

// BuyItem mocks base method.
func (m *MockAppCtrl) BuyItem(ctx context.Context, uid uuid.UUID, item string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "BuyItem", ctx, uid, item)
	ret0, _ := ret[0].(error)
	return ret0
}

// BuyItem indicates an expected call of BuyItem.
func (mr *MockAppCtrlMockRecorder) BuyItem(ctx, uid, item any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BuyItem", reflect.TypeOf((*MockAppCtrl)(nil).BuyItem), ctx, uid, item)
}

// GetInfo mocks base method.
func (m *MockAppCtrl) GetInfo(ctx context.Context, uid uuid.UUID) (*dto.InfoResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetInfo", ctx, uid)
	ret0, _ := ret[0].(*dto.InfoResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInfo indicates an expected call of GetInfo.
func (mr *MockAppCtrlMockRecorder) GetInfo(ctx, uid any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInfo", reflect.TypeOf((*MockAppCtrl)(nil).GetInfo), ctx, uid)
}

// SendCoin mocks base method.
func (m *MockAppCtrl) SendCoin(ctx context.Context, uid uuid.UUID, req *dto.SendCoinRequest) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SendCoin", ctx, uid, req)
	ret0, _ := ret[0].(error)
	return ret0
}

// SendCoin indicates an expected call of SendCoin.
func (mr *MockAppCtrlMockRecorder) SendCoin(ctx, uid, req any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SendCoin", reflect.TypeOf((*MockAppCtrl)(nil).SendCoin), ctx, uid, req)
}
