package tests

import (
	"bytes"
	"encoding/json"
	"github.com/JMURv/avito/internal/dto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"
)

func registerAndLogin(t *testing.T, ts *httptest.Server, username, password string) string {
	regBody := map[string]string{
		"username": username,
		"password": password,
	}
	body, err := json.Marshal(regBody)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenRes dto.TokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenRes)
	require.NoError(t, err)

	return tokenRes.Token
}
