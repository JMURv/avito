package http

import (
	"context"
	"errors"
	"fmt"
	"github.com/JMURv/avito/internal/auth"
	"github.com/JMURv/avito/internal/ctrl"
	mid "github.com/JMURv/avito/internal/hdl/http/middleware"
	"github.com/JMURv/avito/internal/hdl/http/utils"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"
)

type Handler struct {
	srv  *http.Server
	ctrl ctrl.AppCtrl
	au   auth.AuthService
}

func New(auth auth.AuthService, ctrl ctrl.AppCtrl) *Handler {
	return &Handler{
		au:   auth,
		ctrl: ctrl,
	}
}

func (h *Handler) Start(port int) {
	mux := http.NewServeMux()

	RegisterStoreRoutes(mux, h)
	mux.HandleFunc(
		"/health", func(w http.ResponseWriter, r *http.Request) {
			utils.SuccessResponse(w, http.StatusOK, "OK")
		},
	)

	handler := mid.RecoverPanic(mux)
	handler = mid.TracingMiddleware(mux)
	h.srv = &http.Server{
		Handler:      handler,
		Addr:         fmt.Sprintf(":%v", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	err := h.srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		zap.L().Debug("Server error", zap.Error(err))
	}
}

func (h *Handler) Close(ctx context.Context) error {
	return h.srv.Shutdown(ctx)
}

var ErrAuthHeaderIsMissing = errors.New("authorization header is missing")
var ErrInvalidTokenFormat = errors.New("invalid token format")

func (h *Handler) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				utils.ErrResponse(w, http.StatusUnauthorized, ErrAuthHeaderIsMissing)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenStr == authHeader {
				utils.ErrResponse(w, http.StatusUnauthorized, ErrInvalidTokenFormat)
				return
			}

			claims, err := h.au.VerifyToken(tokenStr)
			if err != nil {
				utils.ErrResponse(w, http.StatusUnauthorized, err)
				return
			}

			ctx := context.WithValue(r.Context(), "uid", claims["uid"])
			next.ServeHTTP(w, r.WithContext(ctx))
		},
	)
}
