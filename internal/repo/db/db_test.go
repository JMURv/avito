package db

import (
	"context"
	"database/sql"
	"errors"
	conf "github.com/JMURv/avito/internal/config"
	"github.com/JMURv/avito/internal/dto"
	"github.com/JMURv/avito/internal/model"
	"github.com/JMURv/avito/internal/repo"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/DATA-DOG/go-sqlmock.v1"
	"log"
	"regexp"
	"testing"
)

func TestRepository_GetUserByUsername(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func(db *sql.DB) {
		if err := db.Close(); err != nil {
			log.Println(err)
		}
	}(db)

	name := "username"
	testErr := errors.New("test-err")
	rr := Repository{conn: db}

	tests := []struct {
		name         string
		mockExpect   func()
		expectedResp func(*testing.T, any, error)
	}{
		{
			name: "Success",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(getUser)).
					WithArgs(name).
					WillReturnRows(
						sqlmock.NewRows(
							[]string{
								"id",
								"username",
								"password",
								"balance",
							},
						).AddRow(
							uuid.NewString(),
							"username",
							"password",
							1000,
						),
					)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				resp, ok := res.(*model.User)
				require.True(t, ok)
				assert.Equal(t, name, resp.Username)
			},
		},
		{
			name: "ErrNoRows",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(getUser)).
					WithArgs(name).
					WillReturnError(sql.ErrNoRows)

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, repo.ErrNotFound, err)
			},
		},
		{
			name: "ErrInternal",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(getUser)).
					WithArgs(name).
					WillReturnError(testErr)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				res, err := rr.GetUserByUsername(context.Background(), name)
				tt.expectedResp(t, res, err)
				err = mock.ExpectationsWereMet()
				assert.NoError(t, err)
			},
		)
	}
}

func TestRepository_CreateUser(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func(db *sql.DB) {
		if err := db.Close(); err != nil {
			log.Println(err)
		}
	}(db)

	name := "username"
	pswd := "password"
	uid := uuid.NewString()
	testErr := errors.New("test-err")
	rr := Repository{conn: db}

	tests := []struct {
		name         string
		mockExpect   func()
		expectedResp func(*testing.T, any, error)
	}{
		{
			name: "Success",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(createUser)).
					WithArgs(name, pswd, conf.DefaultBalance).
					WillReturnRows(
						sqlmock.NewRows([]string{"id"}).AddRow(uid),
					)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				resp, ok := res.(uuid.UUID)
				require.True(t, ok)
				assert.Equal(t, uid, resp.String())
			},
		},
		{
			name: "ErrUniqueViolation",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(createUser)).
					WithArgs(name, pswd, conf.DefaultBalance).
					WillReturnError(errors.New("unique constraint violation"))

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, repo.ErrAlreadyExists, err)
			},
		},
		{
			name: "ErrInternal",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(createUser)).
					WithArgs(name, pswd, conf.DefaultBalance).
					WillReturnError(testErr)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				res, err := rr.CreateUser(context.Background(), name, pswd)
				tt.expectedResp(t, res, err)
				err = mock.ExpectationsWereMet()
				assert.NoError(t, err)
			},
		)
	}
}

func TestRepository_GetInfo(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func(db *sql.DB) {
		if err := db.Close(); err != nil {
			log.Println(err)
		}
	}(db)

	coins := 1000
	uid := uuid.NewString()
	testErr := errors.New("test-err")
	page, size := 1, 40
	quantity, itemname := 10, "itemname"
	rr := Repository{conn: db}

	tests := []struct {
		name         string
		mockExpect   func()
		expectedResp func(*testing.T, any, error)
	}{
		{
			name: "getUserBalance -- sql.ErrNoRows",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(getUserBalance)).
					WithArgs(uid).
					WillReturnError(sql.ErrNoRows)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, repo.ErrNotFound, err)
			},
		},
		{
			name: "getUserBalance -- ErrInternal",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(getUserBalance)).
					WithArgs(uid).
					WillReturnError(testErr)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "getUserBalance -- Success",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(getUserBalance)).
					WithArgs(uid).
					WillReturnRows(
						sqlmock.NewRows([]string{"balance"}).AddRow(coins),
					)
			},
			expectedResp: func(t *testing.T, res any, err error) {},
		},
		{
			name: "getUserInventory -- ErrInternal",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(getUserBalance)).
					WithArgs(uid).
					WillReturnRows(
						sqlmock.NewRows([]string{"balance"}).AddRow(coins),
					)

				mock.ExpectQuery(regexp.QuoteMeta(getUserInventory)).
					WithArgs(uid, size, (page-1)*size).
					WillReturnError(testErr)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "getUserInventory -- Success",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(getUserBalance)).
					WithArgs(uid).
					WillReturnRows(
						sqlmock.NewRows([]string{"balance"}).AddRow(coins),
					)

				mock.ExpectQuery(regexp.QuoteMeta(getUserInventory)).
					WithArgs(uid, size, (page-1)*size).
					WillReturnRows(
						sqlmock.NewRows([]string{"quantity", "name"}).AddRow(quantity, itemname),
					)
			},
			expectedResp: func(t *testing.T, res any, err error) {},
		},
		{
			name: "getUserTransactions -- ErrInternal",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(getUserBalance)).
					WithArgs(uid).
					WillReturnRows(
						sqlmock.NewRows([]string{"balance"}).AddRow(coins),
					)

				mock.ExpectQuery(regexp.QuoteMeta(getUserInventory)).
					WithArgs(uid, size, (page-1)*size).
					WillReturnRows(
						sqlmock.NewRows([]string{"quantity", "name"}).AddRow(quantity, itemname),
					)

				mock.ExpectQuery(regexp.QuoteMeta(getUserTransactions)).
					WithArgs(uid, size, (page-1)*size).
					WillReturnError(testErr)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "getUserTransactions -- Success",
			mockExpect: func() {
				mock.ExpectQuery(regexp.QuoteMeta(getUserBalance)).
					WithArgs(uid).
					WillReturnRows(
						sqlmock.NewRows([]string{"balance"}).AddRow(coins),
					)

				mock.ExpectQuery(regexp.QuoteMeta(getUserInventory)).
					WithArgs(uid, size, (page-1)*size).
					WillReturnRows(
						sqlmock.NewRows([]string{"quantity", "name"}).AddRow(quantity, itemname),
					)

				mock.ExpectQuery(regexp.QuoteMeta(getUserTransactions)).
					WithArgs(uid, size, (page-1)*size).
					WillReturnRows(
						sqlmock.NewRows(
							[]string{
								"from_user_id",
								"from_username",
								"to_user_id",
								"to_username",
								"amount",
							},
						).AddRow(
							uid,
							"from_username",
							uuid.NewString(),
							"to_username",
							100,
						).AddRow(
							uuid.NewString(),
							"from_username",
							uid,
							"to_username",
							100,
						),
					)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.NoError(t, err)
				resp, ok := res.(*dto.InfoResponse)
				require.True(t, ok)

				assert.Equal(t, coins, resp.Coins)
				assert.Equal(t, 1, len(resp.Inventory))
				assert.Equal(t, itemname, resp.Inventory[0].Type)
				assert.Equal(t, quantity, resp.Inventory[0].Quantity)

				assert.Equal(t, 1, len(resp.CoinHistory.Sent))
				assert.Equal(t, 1, len(resp.CoinHistory.Received))
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				res, err := rr.GetInfo(context.Background(), uuid.MustParse(uid), page, size)
				tt.expectedResp(t, res, err)
				err = mock.ExpectationsWereMet()
				assert.NoError(t, err)
			},
		)
	}
}

func TestRepository_SendCoin(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func(db *sql.DB) {
		if err := db.Close(); err != nil {
			log.Println(err)
		}
	}(db)

	uid := uuid.NewString()
	testErr := errors.New("test-err")
	req := &dto.SendCoinRequest{
		ToUser: "to_username",
		Amount: 100,
	}

	rr := Repository{conn: db}

	tests := []struct {
		name         string
		mockExpect   func()
		expectedResp func(*testing.T, any, error)
	}{
		{
			name: "BeginErr -- ErrInternal",
			mockExpect: func() {
				mock.ExpectBegin().WillReturnError(testErr)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "sendCoinFrom -- RollbackErr",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnError(testErr)

				mock.ExpectRollback().WillReturnError(testErr)

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "sendCoinFrom -- ErrInternal",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnError(testErr)

				mock.ExpectRollback()

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "sendCoinFrom -- No rows affected",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnResult(sqlmock.NewResult(0, 0))

				mock.ExpectRollback()
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, err)
			},
		},
		{
			name: "sendCoinFrom -- Success",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))

			},
			expectedResp: func(t *testing.T, res any, err error) {},
		},
		{
			name: "sendCoinTo -- RollbackErr",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(sendCoinTo)).
					WithArgs(req.Amount, req.ToUser).
					WillReturnError(testErr)

				mock.ExpectRollback().WillReturnError(testErr)

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "sendCoinTo -- ErrInternal",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(sendCoinTo)).
					WithArgs(req.Amount, req.ToUser).
					WillReturnError(testErr)

				mock.ExpectRollback()

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "sendCoinTo -- No rows affected",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(sendCoinTo)).
					WithArgs(req.Amount, req.ToUser).
					WillReturnResult(sqlmock.NewResult(0, 0))

				mock.ExpectRollback()
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Nil(t, err)
			},
		},
		{
			name: "sendCoinTo -- Success",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(sendCoinTo)).
					WithArgs(req.Amount, req.ToUser).
					WillReturnResult(sqlmock.NewResult(1, 1))

			},
			expectedResp: func(t *testing.T, res any, err error) {},
		},
		{
			name: "createTransaction -- RollbackErr",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(sendCoinTo)).
					WithArgs(req.Amount, req.ToUser).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(createTransaction)).
					WithArgs(uid, req.ToUser, req.Amount).
					WillReturnError(testErr)

				mock.ExpectRollback().WillReturnError(testErr)

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "createTransaction -- InternalErr",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(sendCoinTo)).
					WithArgs(req.Amount, req.ToUser).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(createTransaction)).
					WithArgs(uid, req.ToUser, req.Amount).
					WillReturnError(testErr)

				mock.ExpectRollback()

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "createTransaction -- Success",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(req.Amount, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(sendCoinTo)).
					WithArgs(req.Amount, req.ToUser).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(createTransaction)).
					WithArgs(uid, req.ToUser, req.Amount).
					WillReturnResult(sqlmock.NewResult(1, 1))

			},
			expectedResp: func(t *testing.T, res any, err error) {},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				err := rr.SendCoin(context.Background(), uuid.MustParse(uid), req)
				tt.expectedResp(t, nil, err)
				err = mock.ExpectationsWereMet()
				assert.NoError(t, err)
			},
		)
	}
}

func TestRepository_BuyItem(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer func(db *sql.DB) {
		if err := db.Close(); err != nil {
			log.Println(err)
		}
	}(db)

	uid := uuid.NewString()
	item := "itemname"
	testErr := errors.New("test-err")
	itemObj := model.Item{
		ID:    uuid.New(),
		Name:  "itemname",
		Price: 100,
	}
	rr := Repository{conn: db}

	tests := []struct {
		name         string
		mockExpect   func()
		expectedResp func(*testing.T, any, error)
	}{
		{
			name: "BeginErr -- ErrInternal",
			mockExpect: func() {
				mock.ExpectBegin().WillReturnError(testErr)
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "getItem -- ErrNotFound",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectQuery(regexp.QuoteMeta(getItem)).
					WithArgs(item).
					WillReturnError(sql.ErrNoRows)

				mock.ExpectRollback()
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, repo.ErrNotFound, err)
			},
		},
		{
			name: "getItem -- ErrInternal",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectQuery(regexp.QuoteMeta(getItem)).
					WithArgs(item).
					WillReturnError(testErr)

				mock.ExpectRollback()
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "sendCoinFrom -- RollbackErr",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectQuery(regexp.QuoteMeta(getItem)).
					WithArgs(item).
					WillReturnRows(
						sqlmock.NewRows([]string{"id", "name", "price"}).AddRow(
							itemObj.ID.String(),
							itemObj.Name,
							itemObj.Price,
						),
					)

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(itemObj.Price, uid).
					WillReturnError(testErr)

				mock.ExpectRollback().WillReturnError(testErr)

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "sendCoinFrom -- ErrInternal",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectQuery(regexp.QuoteMeta(getItem)).
					WithArgs(item).
					WillReturnRows(
						sqlmock.NewRows([]string{"id", "name", "price"}).AddRow(
							itemObj.ID.String(),
							itemObj.Name,
							itemObj.Price,
						),
					)

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(itemObj.Price, uid).
					WillReturnError(testErr)

				mock.ExpectRollback()

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "sendCoinFrom -- No rows affected",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectQuery(regexp.QuoteMeta(getItem)).
					WithArgs(item).
					WillReturnRows(
						sqlmock.NewRows([]string{"id", "name", "price"}).AddRow(
							itemObj.ID.String(),
							itemObj.Name,
							itemObj.Price,
						),
					)

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(itemObj.Price, uid).
					WillReturnResult(sqlmock.NewResult(0, 0))

				mock.ExpectRollback()
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, repo.ErrNotFound, err)
			},
		},
		{
			name: "sendCoinFrom -- Success",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectQuery(regexp.QuoteMeta(getItem)).
					WithArgs(item).
					WillReturnRows(
						sqlmock.NewRows([]string{"id", "name", "price"}).AddRow(
							itemObj.ID.String(),
							itemObj.Name,
							itemObj.Price,
						),
					)

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(itemObj.Price, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
			expectedResp: func(t *testing.T, res any, err error) {},
		},
		{
			name: "upsertInventory -- ErrInternal",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectQuery(regexp.QuoteMeta(getItem)).
					WithArgs(item).
					WillReturnRows(
						sqlmock.NewRows([]string{"id", "name", "price"}).AddRow(
							itemObj.ID.String(),
							itemObj.Name,
							itemObj.Price,
						),
					)

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(itemObj.Price, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(upsertInventory)).
					WithArgs(uid, itemObj.ID).
					WillReturnError(testErr)

				mock.ExpectRollback()

			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.Error(t, err)
				assert.Equal(t, testErr, err)
			},
		},
		{
			name: "upsertInventory -- Success",
			mockExpect: func() {
				mock.ExpectBegin()

				mock.ExpectQuery(regexp.QuoteMeta(getItem)).
					WithArgs(item).
					WillReturnRows(
						sqlmock.NewRows([]string{"id", "name", "price"}).AddRow(
							itemObj.ID.String(),
							itemObj.Name,
							itemObj.Price,
						),
					)

				mock.ExpectExec(regexp.QuoteMeta(sendCoinFrom)).
					WithArgs(itemObj.Price, uid).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectExec(regexp.QuoteMeta(upsertInventory)).
					WithArgs(uid, itemObj.ID).
					WillReturnResult(sqlmock.NewResult(1, 1))

				mock.ExpectCommit()
			},
			expectedResp: func(t *testing.T, res any, err error) {
				assert.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				tt.mockExpect()
				err := rr.BuyItem(context.Background(), uuid.MustParse(uid), item)
				tt.expectedResp(t, nil, err)
				err = mock.ExpectationsWereMet()
				assert.NoError(t, err)
			},
		)
	}
}
