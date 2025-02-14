package mappers

import (
	"github.com/JMURv/avito/api/grpc/gen"
	"github.com/JMURv/avito/internal/dto"
)

func InfoToProto(req *dto.InfoResponse) *gen.InfoResponse {
	inv := make([]*gen.Inventory, 0, len(req.Inventory))
	for i := 0; i < len(req.Inventory); i++ {
		inv = append(
			inv, &gen.Inventory{
				Type:     req.Inventory[i].Type,
				Quantity: int32(req.Inventory[i].Quantity),
			},
		)
	}

	recv := make([]*gen.ReceivedCoins, 0, len(req.CoinHistory.Received))
	for i := 0; i < len(req.CoinHistory.Received); i++ {
		recv = append(
			recv, &gen.ReceivedCoins{
				FromUser: req.CoinHistory.Received[i].FromUser,
				Amount:   int64(req.CoinHistory.Received[i].Amount),
			},
		)
	}

	sent := make([]*gen.SentCoins, 0, len(req.CoinHistory.Sent))
	for i := 0; i < len(req.CoinHistory.Sent); i++ {
		sent = append(
			sent, &gen.SentCoins{
				ToUser: req.CoinHistory.Sent[i].ToUser,
				Amount: int64(req.CoinHistory.Sent[i].Amount),
			},
		)
	}

	return &gen.InfoResponse{
		Coins:     int64(req.Coins),
		Inventory: inv,
		CoinHistory: &gen.CoinHistory{
			Received: recv,
			Sent:     sent,
		},
	}
}
