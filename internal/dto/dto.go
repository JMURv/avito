package dto

type TokenResponse struct {
	Token string `json:"token"`
}

type SendCoinRequest struct {
	ToUser string `json:"toUser"`
	Amount int    `json:"amount"`
}

type InfoResponse struct {
	Coins       int         `json:"coins"`
	Inventory   []Inventory `json:"inventory"`
	CoinHistory struct {
		Received []ReceivedCoins `json:"received"`
		Sent     []SentCoins     `json:"sent"`
	} `json:"coinHistory"`
}

type Inventory struct {
	Type     string `json:"type"`
	Quantity int    `json:"quantity"`
}

type ReceivedCoins struct {
	FromUser string `json:"fromUser"`
	Amount   int    `json:"amount"`
}

type SentCoins struct {
	ToUser string `json:"toUser"`
	Amount int    `json:"amount"`
}
