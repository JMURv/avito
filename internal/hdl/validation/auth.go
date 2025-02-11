package validation

import (
	"github.com/JMURv/avito/pkg/model"
)

func AuthReq(req *model.User) error {
	if req.Username == "" {
		return UsernameIsRequired
	}

	if req.Password == "" {
		return PasswordIsRequired
	}

	if len(req.Password) > 5 {
		return PasswordIsTooShort
	}

	return nil
}

func SendCoinReq(req *model.SendCoinRequest) error {
	if req.ToUser == "" {
		return ToUserIsRequired
	}

	if req.Amount == 0 {
		return AmountIsRequired
	}

	return nil
}
