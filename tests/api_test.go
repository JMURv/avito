package tests

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/JMURv/avito/internal/auth"
	"github.com/JMURv/avito/internal/config"
	"github.com/JMURv/avito/internal/ctrl"
	"github.com/JMURv/avito/internal/dto"
	hdlr "github.com/JMURv/avito/internal/hdl"
	hdl "github.com/JMURv/avito/internal/hdl/http"
	"github.com/JMURv/avito/internal/hdl/http/utils"
	"github.com/JMURv/avito/internal/hdl/validation"
	"github.com/JMURv/avito/internal/repo/db"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const configPath = "../configs/test.config.yaml"
const getTables = `
SELECT tablename 
FROM pg_tables 
WHERE schemaname = 'public';
`

func setupTestServer() (*httptest.Server, auth.AuthService, func()) {
	zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))

	conf := config.MustLoad(configPath)
	au := auth.New(conf.Secret)
	repo := db.New(conf.DB)
	svc := ctrl.New(au, repo)
	h := hdl.New(au, svc)

	mux := http.NewServeMux()
	hdl.RegisterStoreRoutes(mux, h)

	cleanupFunc := func() {
		conn, err := sql.Open(
			"postgres", fmt.Sprintf(
				"postgres://%s:%s@%s:%d/%s?sslmode=disable",
				conf.DB.User,
				conf.DB.Password,
				conf.DB.Host,
				conf.DB.Port,
				conf.DB.Database,
			),
		)
		if err != nil {
			zap.L().Fatal("Failed to connect to the database", zap.Error(err))
		}

		if err = conn.Ping(); err != nil {
			zap.L().Fatal("Failed to ping the database", zap.Error(err))
		}

		rows, err := conn.Query(getTables)
		if err != nil {
			zap.L().Fatal("Failed to fetch table names", zap.Error(err))
		}
		defer func(rows *sql.Rows) {
			if err := rows.Close(); err != nil {
				zap.L().Debug("Error while closing rows", zap.Error(err))
			}
		}(rows)

		var tables []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				zap.L().Fatal("Failed to scan table name", zap.Error(err))
			}
			tables = append(tables, name)
		}

		if len(tables) == 0 {
			return
		}

		_, err = conn.Exec(fmt.Sprintf("TRUNCATE TABLE %v RESTART IDENTITY CASCADE;", strings.Join(tables, ", ")))
		if err != nil {
			zap.L().Fatal("Failed to truncate tables", zap.Error(err))
		}
	}

	return httptest.NewServer(mux), au, cleanupFunc
}

func TestOverall(t *testing.T) {
	const (
		getInfoURI  = "/api/info"
		sendCoinURI = "/api/sendCoin"
		buyItemURI  = "/api/buy/"
	)

	ts, _, cleanUp := setupTestServer()
	defer ts.Close()
	t.Cleanup(cleanUp)

	user1name := "user1"
	user1Token := registerAndLogin(t, ts, user1name, "pass1")

	user2name := "user2"
	user2Token := registerAndLogin(t, ts, user2name, "pass2")

	getUserInfo := func(t *testing.T, token string) dto.InfoResponse {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+getInfoURI, nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func(Body io.ReadCloser) {
			if err := Body.Close(); err != nil {
				zap.L().Debug("Error while closing body", zap.Error(err))
			}
		}(resp.Body)

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var info dto.InfoResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&info))
		return info
	}

	sendCoins := func(t *testing.T, senderToken string, receiverUsername string, amount int) {
		body, _ := json.Marshal(
			map[string]interface{}{
				"toUser": receiverUsername,
				"amount": amount,
			},
		)

		req, _ := http.NewRequest(
			http.MethodPost,
			ts.URL+sendCoinURI,
			bytes.NewReader(body),
		)
		req.Header.Set("Authorization", "Bearer "+senderToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer func(Body io.ReadCloser) {
			if err := Body.Close(); err != nil {
				zap.L().Debug("Error while closing body", zap.Error(err))
			}
		}(resp.Body)
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	buyItem := func(t *testing.T, token string, item string) {
		req, _ := http.NewRequest(
			http.MethodGet,
			ts.URL+buyItemURI+item,
			nil,
		)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	t.Run(
		"Initial balances", func(t *testing.T) {
			user1Info := getUserInfo(t, user1Token)
			user2Info := getUserInfo(t, user2Token)
			assert.Equal(t, config.DefaultBalance, user1Info.Coins)
			assert.Equal(t, config.DefaultBalance, user2Info.Coins)
		},
	)

	t.Run(
		"Send coins between users", func(t *testing.T) {
			sendCoins(t, user1Token, user2name, 200)

			user1Info := getUserInfo(t, user1Token)
			user2Info := getUserInfo(t, user2Token)
			assert.Equal(t, 800, user1Info.Coins)
			assert.Equal(t, 1200, user2Info.Coins)
			require.Len(t, user1Info.CoinHistory.Sent, 1)
			assert.Equal(t, user2name, user1Info.CoinHistory.Sent[0].ToUser)
			assert.Equal(t, 200, user1Info.CoinHistory.Sent[0].Amount)
			require.Len(t, user2Info.CoinHistory.Received, 1)
			assert.Equal(t, user1name, user2Info.CoinHistory.Received[0].FromUser)
			assert.Equal(t, 200, user2Info.CoinHistory.Received[0].Amount)

			sendCoins(t, user2Token, user1name, 100)
			user1Info = getUserInfo(t, user1Token)
			user2Info = getUserInfo(t, user2Token)
			assert.Equal(t, 900, user1Info.Coins)
			assert.Equal(t, 1100, user2Info.Coins)
		},
	)

	t.Run(
		"Purchase items and verify inventory", func(t *testing.T) {
			buyItem(t, user1Token, "powerbank")
			buyItem(t, user2Token, "hoody")

			user1Info := getUserInfo(t, user1Token)
			user2Info := getUserInfo(t, user2Token)
			assert.Equal(t, 700, user1Info.Coins) // 900 - 200
			assert.Equal(t, 800, user2Info.Coins) // 1100 - 300

			require.Len(t, user1Info.Inventory, 1)
			assert.Equal(t, "powerbank", user1Info.Inventory[0].Type)
			assert.Equal(t, 1, user1Info.Inventory[0].Quantity)
			require.Len(t, user2Info.Inventory, 1)
			assert.Equal(t, "hoody", user2Info.Inventory[0].Type)
			assert.Equal(t, 1, user2Info.Inventory[0].Quantity)
		},
	)
}

func TestAuth(t *testing.T) {
	const uri = "/api/auth"
	ts, _, cleanUp := setupTestServer()
	defer ts.Close()
	t.Cleanup(cleanUp)

	tests := []struct {
		name         string
		method       string
		body         any
		resType      any
		status       int
		expectedResp func(*testing.T, any)
	}{
		{
			name:   "Invalid Method",
			method: http.MethodGet,
			body: map[string]string{
				"username": "john doe",
				"password": "testpass",
			},
			resType: &utils.ErrorResponse{},
			status:  http.StatusMethodNotAllowed,
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.NotEmpty(t, res.Errors)
				assert.Equal(t, hdl.ErrMethodNotAllowed.Error(), res.Errors)
			},
		},
		{
			name:   "ErrDecodeRequest",
			method: http.MethodPost,
			body: map[string]any{
				"username": "john doe",
				"password": 123456,
			},
			resType: &utils.ErrorResponse{},
			status:  http.StatusBadRequest,
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.NotEmpty(t, res.Errors)
				assert.Equal(t, hdlr.ErrDecodeRequest.Error(), res.Errors)
			},
		},
		{
			name:   "Success register",
			method: http.MethodPost,
			body: map[string]string{
				"username": "john doe",
				"password": "testpass",
			},
			resType: &dto.TokenResponse{},
			status:  http.StatusOK,
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*dto.TokenResponse)
				assert.NotEmpty(t, res.Token)
			},
		},
		{
			name:   "Success sign-in",
			method: http.MethodPost,
			body: map[string]string{
				"username": "john doe",
				"password": "testpass",
			},
			resType: &dto.TokenResponse{},
			status:  http.StatusOK,
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*dto.TokenResponse)
				assert.NotEmpty(t, res.Token)
			},
		},
		{
			name:   "Invalid credentials",
			method: http.MethodPost,
			body: map[string]string{
				"username": "john doe",
				"password": "12345",
			},
			resType: &utils.ErrorResponse{},
			status:  http.StatusUnauthorized,
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.NotEmpty(t, res.Errors)
				assert.Equal(t, auth.ErrInvalidCredentials.Error(), res.Errors)
			},
		},
		{
			name:   "Validation: UsernameIsRequired",
			method: http.MethodPost,
			body: map[string]string{
				"username": "",
				"password": "1234",
			},
			resType: &utils.ErrorResponse{},
			status:  http.StatusBadRequest,
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.NotEmpty(t, res.Errors)
				assert.Equal(t, validation.UsernameIsRequired.Error(), res.Errors)
			},
		},
		{
			name:   "Validation: PasswordIsRequired",
			method: http.MethodPost,
			body: map[string]string{
				"username": "john doe",
				"password": "",
			},
			resType: &utils.ErrorResponse{},
			status:  http.StatusBadRequest,
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.NotEmpty(t, res.Errors)
				assert.Equal(t, validation.PasswordIsRequired.Error(), res.Errors)
			},
		},
		{
			name:   "Validation: PasswordIsTooShort",
			method: http.MethodPost,
			body: map[string]string{
				"username": "john doe",
				"password": "1234",
			},
			resType: &utils.ErrorResponse{},
			status:  http.StatusBadRequest,
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.NotEmpty(t, res.Errors)
				assert.Equal(t, validation.PasswordIsTooShort.Error(), res.Errors)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				body, err := json.Marshal(tt.body)
				require.Nil(t, err)

				req, err := http.NewRequest(tt.method, ts.URL+uri, bytes.NewReader(body))
				require.Nil(t, err)
				req.Header.Set("Content-Type", "application/json")

				client := &http.Client{}
				resp, err := client.Do(req)
				require.Nil(t, err)
				defer func(Body io.ReadCloser) {
					if err := Body.Close(); err != nil {
						t.Error(err)
					}
				}(resp.Body)

				res := tt.resType
				err = json.NewDecoder(resp.Body).Decode(res)
				assert.NoError(t, err)

				assert.Equal(t, tt.status, resp.StatusCode)
				tt.expectedResp(t, res)
			},
		)
	}
}

func TestGetInfo(t *testing.T) {
	const uri = "/api/info"
	ts, _, cleanUp := setupTestServer()
	defer ts.Close()
	t.Cleanup(cleanUp)

	token := registerAndLogin(t, ts, "username", "password")
	tests := []struct {
		name         string
		method       string
		headers      map[string]string
		queryParams  map[string]string
		status       int
		resType      any
		expectedResp func(*testing.T, any)
	}{
		{
			name:   "Invalid Method",
			method: http.MethodPost,
			headers: map[string]string{
				"Authorization": "Bearer " + token,
			},
			status:  http.StatusMethodNotAllowed,
			resType: &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdl.ErrMethodNotAllowed.Error(), res.Errors)
			},
		},
		{
			name:    "Missing Authorization Header",
			method:  http.MethodGet,
			status:  http.StatusUnauthorized,
			resType: &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdl.ErrAuthHeaderIsMissing.Error(), res.Errors)
			},
		},
		{
			name:   "Invalid Token Format",
			method: http.MethodGet,
			headers: map[string]string{
				"Authorization": "invalidtoken",
			},
			status:  http.StatusUnauthorized,
			resType: &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdl.ErrInvalidTokenFormat.Error(), res.Errors)
			},
		},
		{
			name:   "Invalid Token",
			method: http.MethodGet,
			headers: map[string]string{
				"Authorization": "Bearer invalidtoken",
			},
			status:  http.StatusUnauthorized,
			resType: &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Contains(t, res.Errors, jwt.ErrTokenMalformed.Error())
			},
		},
		{
			name:   "Invalid Page and Size Parameters",
			method: http.MethodGet,
			headers: map[string]string{
				"Authorization": "Bearer " + token,
			},
			queryParams: map[string]string{
				"page": "abc",
				"size": "def",
			},
			status:  http.StatusOK,
			resType: &dto.InfoResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*dto.InfoResponse)
				assert.NotNil(t, res)
			},
		},
		{
			name:   "Success with Valid Parameters",
			method: http.MethodGet,
			headers: map[string]string{
				"Authorization": "Bearer " + token,
			},
			queryParams: map[string]string{
				"page": "2",
				"size": "20",
			},
			status:  http.StatusOK,
			resType: &dto.InfoResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*dto.InfoResponse)
				assert.Equal(t, config.DefaultBalance, res.Coins)
				assert.NotNil(t, res)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				link := ts.URL + uri

				if len(tt.queryParams) > 0 {
					params := url.Values{}
					for k, v := range tt.queryParams {
						params.Add(k, v)
					}
					link += "?" + params.Encode()
				}

				req, err := http.NewRequest(tt.method, link, nil)
				require.NoError(t, err)

				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}

				client := &http.Client{}
				resp, err := client.Do(req)
				require.NoError(t, err)
				defer func(Body io.ReadCloser) {
					if err := Body.Close(); err != nil {
						zap.L().Debug("Error while closing body", zap.Error(err))
					}
				}(resp.Body)

				res := tt.resType
				err = json.NewDecoder(resp.Body).Decode(res)
				assert.NoError(t, err)

				assert.Equal(t, tt.status, resp.StatusCode)
				tt.expectedResp(t, res)
			},
		)
	}
}

func TestSendCoin(t *testing.T) {
	const uri = "/api/sendCoin"
	ts, au, cleanUp := setupTestServer()
	defer ts.Close()
	t.Cleanup(cleanUp)

	senderToken := registerAndLogin(t, ts, "sender_user", "sender_pass")
	receiverToken := registerAndLogin(t, ts, "receiver_user", "receiver_pass")
	receiverClaims, _ := au.VerifyToken(receiverToken)
	receiverUID := receiverClaims["uid"].(string)

	tests := []struct {
		name         string
		method       string
		headers      map[string]string
		body         any
		status       int
		resType      any
		expectedResp func(*testing.T, any)
	}{
		{
			name:   "Invalid Method",
			method: http.MethodGet,
			headers: map[string]string{
				"Authorization": "Bearer " + senderToken,
			},
			status:  http.StatusMethodNotAllowed,
			resType: &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdl.ErrMethodNotAllowed.Error(), res.Errors)
			},
		},
		{
			name:    "Missing Authorization",
			method:  http.MethodPost,
			status:  http.StatusUnauthorized,
			resType: &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdl.ErrAuthHeaderIsMissing.Error(), res.Errors)
			},
		},
		{
			name:   "Invalid Token Format",
			method: http.MethodPost,
			headers: map[string]string{
				"Authorization": "invalid_token",
			},
			status:  http.StatusUnauthorized,
			resType: &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdl.ErrInvalidTokenFormat.Error(), res.Errors)
			},
		},
		{
			name:   "Malformed JSON Body",
			method: http.MethodPost,
			headers: map[string]string{
				"Authorization": "Bearer " + senderToken,
			},
			body: map[string]any{
				"toUser": receiverUID,
				"amount": "ten",
			},
			status:  http.StatusBadRequest,
			resType: &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Contains(t, res.Errors, hdlr.ErrDecodeRequest.Error())
			},
		},
		{
			name:   "Negative Amount",
			method: http.MethodPost,
			headers: map[string]string{
				"Authorization": "Bearer " + senderToken,
			},
			body: map[string]any{
				"toUser": receiverUID,
				"amount": -100,
			},
			status:  http.StatusBadRequest,
			resType: &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Contains(t, res.Errors, validation.AmountIsRequired.Error())
			},
		},
		{
			name:   "Insufficient Funds",
			method: http.MethodPost,
			headers: map[string]string{
				"Authorization": "Bearer " + senderToken,
			},
			body: map[string]any{
				"toUser": receiverUID,
				"amount": 10000,
			},
			status:  http.StatusInternalServerError,
			resType: &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdlr.ErrInternal.Error(), res.Errors)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				var bodyBytes []byte
				switch v := tt.body.(type) {
				case string:
					bodyBytes = []byte(v)
				default:
					var err error
					bodyBytes, err = json.Marshal(tt.body)
					require.NoError(t, err)
				}

				req, err := http.NewRequest(tt.method, ts.URL+uri, bytes.NewReader(bodyBytes))
				require.NoError(t, err)

				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}
				req.Header.Set("Content-Type", "application/json")

				client := &http.Client{}
				resp, err := client.Do(req)
				require.NoError(t, err)
				defer func(Body io.ReadCloser) {
					if err := Body.Close(); err != nil {
						zap.L().Debug("Error while closing body", zap.Error(err))
					}
				}(resp.Body)

				assert.Equal(t, tt.status, resp.StatusCode)

				res := tt.resType
				err = json.NewDecoder(resp.Body).Decode(res)
				assert.NoError(t, err)

				assert.Equal(t, tt.status, resp.StatusCode)
				tt.expectedResp(t, res)
			},
		)
	}
}

func TestBuyItem(t *testing.T) {
	const baseURI = "/api/buy/"
	ts, _, cleanUp := setupTestServer()
	defer ts.Close()
	t.Cleanup(cleanUp)

	validToken := registerAndLogin(t, ts, "testuser", "testpass")
	tests := []struct {
		name         string
		method       string
		headers      map[string]string
		pathSuffix   string
		status       int
		resType      any
		expectedResp func(*testing.T, any)
	}{
		{
			name:       "Invalid Method",
			method:     http.MethodPost,
			headers:    map[string]string{"Authorization": "Bearer " + validToken},
			pathSuffix: "valid_item",
			status:     http.StatusMethodNotAllowed,
			resType:    &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdl.ErrMethodNotAllowed.Error(), res.Errors)
			},
		},
		{
			name:       "Missing Authorization",
			method:     http.MethodGet,
			pathSuffix: "valid_item",
			status:     http.StatusUnauthorized,
			resType:    &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdl.ErrAuthHeaderIsMissing.Error(), res.Errors)
			},
		},
		{
			name:       "Invalid Token Format",
			method:     http.MethodGet,
			headers:    map[string]string{"Authorization": "invalid_token"},
			pathSuffix: "valid_item",
			status:     http.StatusUnauthorized,
			resType:    &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdl.ErrInvalidTokenFormat.Error(), res.Errors)
			},
		},
		{
			name:       "Expired Token",
			method:     http.MethodGet,
			headers:    map[string]string{"Authorization": "Bearer expired_token"},
			pathSuffix: "valid_item",
			status:     http.StatusUnauthorized,
			resType:    &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Contains(t, res.Errors, jwt.ErrTokenMalformed.Error())
			},
		},
		{
			name:       "Missing Item",
			method:     http.MethodGet,
			headers:    map[string]string{"Authorization": "Bearer " + validToken},
			pathSuffix: "",
			status:     http.StatusBadRequest,
			resType:    &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdl.ErrItemIsRequired.Error(), res.Errors)
			},
		},
		{
			name:       "Successful Purchase",
			method:     http.MethodGet,
			headers:    map[string]string{"Authorization": "Bearer " + validToken},
			pathSuffix: "pink-hoody",
			status:     http.StatusOK,
			resType:    nil,
		},
		{
			name:       "Insufficient Funds",
			method:     http.MethodGet,
			headers:    map[string]string{"Authorization": "Bearer " + validToken},
			pathSuffix: "expensive_item",
			status:     http.StatusInternalServerError,
			resType:    &utils.ErrorResponse{},
			expectedResp: func(t *testing.T, actual any) {
				res := actual.(*utils.ErrorResponse)
				assert.Equal(t, hdlr.ErrInternal.Error(), res.Errors)
			},
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				fullURL := ts.URL + baseURI + tt.pathSuffix
				req, err := http.NewRequest(tt.method, fullURL, nil)
				require.NoError(t, err)

				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}

				client := &http.Client{}
				resp, err := client.Do(req)
				require.NoError(t, err)
				defer resp.Body.Close()

				assert.Equal(t, tt.status, resp.StatusCode)
				if tt.resType != nil {
					res := tt.resType
					err = json.NewDecoder(resp.Body).Decode(res)
					assert.NoError(t, err)

					assert.Equal(t, tt.status, resp.StatusCode)
					tt.expectedResp(t, res)
				} else if tt.status == http.StatusOK {
					body, err := io.ReadAll(resp.Body)
					require.NoError(t, err)
					assert.Empty(t, body)
				}
			},
		)
	}
}
