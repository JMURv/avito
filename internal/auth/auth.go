package auth

import (
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"time"
)

const AccessTokenDuration = time.Hour * 72

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrInvalidToken = errors.New("invalid token")

type AuthService interface {
	NewToken(uid uuid.UUID) (string, error)
	VerifyToken(tokenStr string) (map[string]any, error)
	HashPassword(password string) (string, error)
	ComparePasswords(pswd, pswdCompare []byte) error
}

type Auth struct {
	secret string
}

func New(secret string) *Auth {
	return &Auth{secret: secret}
}

func (a *Auth) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (a *Auth) ComparePasswords(pswd, pswdCompare []byte) error {
	if err := bcrypt.CompareHashAndPassword(pswd, pswdCompare); err != nil {
		return ErrInvalidCredentials
	}
	return nil
}

func (a *Auth) NewToken(uid uuid.UUID) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = uid
	claims["exp"] = time.Now().Add(AccessTokenDuration).Unix()

	signed, err := token.SignedString([]byte(a.secret))
	if err != nil {
		return "", err
	}

	return signed, nil
}

func (a *Auth) VerifyToken(tokenStr string) (map[string]any, error) {
	token, err := jwt.Parse(
		tokenStr, func(token *jwt.Token) (any, error) {
			return []byte(a.secret), nil
		},
	)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, ErrInvalidToken
	}
}
