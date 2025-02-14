package validation

import (
	"github.com/JMURv/avito/internal/dto"
	"github.com/JMURv/avito/internal/model"
)

func AuthReq(req *model.User) error {
	if req.Username == "" {
		return UsernameIsRequired
	}

	if req.Password == "" {
		return PasswordIsRequired
	}

	if len(req.Password) < 5 {
		return PasswordIsTooShort
	}

	return nil
}

func SendCoinReq(req *dto.SendCoinRequest) error {
	if req.ToUser == "" {
		return ToUserIsRequired
	}

	if req.Amount == 0 {
		return AmountIsRequired
	}

	return nil
}
