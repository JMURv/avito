package model

import "github.com/google/uuid"

type User struct {
	ID       uuid.UUID `json:"id"`
	Username string    `json:"username"`
	Balance  int       `json:"balance"`
	Password string    `json:"password"`
}
