package http

import "errors"

var ErrInternal = errors.New("internal error")
var ErrDecodeRequest = errors.New("decode request")
var ErrAlreadyExists = errors.New("already exists")
var ErrItemIsRequired = errors.New("item is required")
