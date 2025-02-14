package http

import "errors"

var ErrMethodNotAllowed = errors.New("method not allowed")
var ErrItemIsRequired = errors.New("item is required")
