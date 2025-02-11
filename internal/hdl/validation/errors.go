package validation

import "errors"

var UsernameIsRequired = errors.New("username is required")

var PasswordIsRequired = errors.New("password is required")
var PasswordIsTooShort = errors.New("password is too short")

var ToUserIsRequired = errors.New("toUser is required")
var AmountIsRequired = errors.New("amount is required")
