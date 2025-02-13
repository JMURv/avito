package http

import (
	"encoding/json"
	"errors"
	"github.com/JMURv/avito/internal/auth"
	"github.com/JMURv/avito/internal/ctrl"
	"github.com/JMURv/avito/internal/hdl/http/middleware"
	"github.com/JMURv/avito/internal/hdl/http/utils"
	"github.com/JMURv/avito/internal/hdl/validation"
	metrics "github.com/JMURv/avito/internal/observability/metrics/prometheus"
	"github.com/JMURv/avito/pkg/model"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net/http"
	"strings"
	"time"
)

// TODO: Logs to hdls

func RegisterStoreRoutes(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("/api/auth", h.auth)
	mux.HandleFunc("/api/info", middleware.ApplyMiddleware(h.getInfo, h.authMiddleware))
	mux.HandleFunc("/api/sendCoin", middleware.ApplyMiddleware(h.sendCoin, h.authMiddleware))
	mux.HandleFunc("/api/buy/", middleware.ApplyMiddleware(h.buyItem, h.authMiddleware))
}

func (h *Handler) auth(w http.ResponseWriter, r *http.Request) {
	s, c := time.Now(), http.StatusOK
	const op = "store.auth.hdl"
	defer func() {
		metrics.ObserveRequest(time.Since(s), c, op)
	}()

	req := &model.User{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		c = http.StatusBadRequest
		zap.L().Debug(
			"failed to decode request",
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, ErrDecodeRequest)
		return
	}

	if err := validation.AuthReq(req); err != nil {
		c = http.StatusBadRequest
		zap.L().Debug(
			"failed to validate credentials",
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, err)
		return
	}

	token, err := h.ctrl.AuthUser(r.Context(), req)
	if err != nil && errors.Is(err, auth.ErrInvalidCredentials) {
		c = http.StatusUnauthorized
		utils.ErrResponse(w, c, err)
		return
	} else if err != nil && errors.Is(err, ctrl.ErrAlreadyExists) {
		c = http.StatusConflict
		utils.ErrResponse(w, c, ErrAlreadyExists)
		return
	} else if err != nil {
		c = http.StatusInternalServerError
		utils.ErrResponse(w, c, ErrInternal)
		return
	}

	utils.SuccessResponse(w, c, token)
}

func (h *Handler) getInfo(w http.ResponseWriter, r *http.Request) {
	s, c := time.Now(), http.StatusOK
	const op = "store.getInfo.hdl"
	defer func() {
		metrics.ObserveRequest(time.Since(s), c, op)
	}()

	uidStr, ok := r.Context().Value("uid").(string)
	if !ok {
		c = http.StatusBadRequest
		utils.ErrResponse(w, c, ErrDecodeRequest)
		return
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		c = http.StatusBadRequest
		utils.ErrResponse(w, c, ErrDecodeRequest)
		return
	}

	res, err := h.ctrl.GetInfo(r.Context(), uid)
	if err != nil {
		c = http.StatusInternalServerError
		utils.ErrResponse(w, c, ErrInternal)
		return
	}

	utils.SuccessResponse(w, c, res)
}

func (h *Handler) sendCoin(w http.ResponseWriter, r *http.Request) {
	s, c := time.Now(), http.StatusOK
	const op = "store.sendCoin.hdl"
	defer func() {
		metrics.ObserveRequest(time.Since(s), c, op)
	}()

	uidStr, ok := r.Context().Value("uid").(string)
	if !ok {
		c = http.StatusBadRequest
		utils.ErrResponse(w, c, ErrDecodeRequest)
		return
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		c = http.StatusBadRequest
		utils.ErrResponse(w, c, ErrDecodeRequest)
		return
	}

	req := &model.SendCoinRequest{}
	if err = json.NewDecoder(r.Body).Decode(req); err != nil {
		c = http.StatusBadRequest
		zap.L().Debug(
			"failed to decode request",
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, ErrDecodeRequest)
		return
	}

	if err = validation.SendCoinReq(req); err != nil {
		c = http.StatusBadRequest
		zap.L().Debug(
			"failed to validate credentials",
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, err)
		return
	}

	err = h.ctrl.SendCoin(r.Context(), uid, req)
	if err != nil {
		c = http.StatusInternalServerError
		utils.ErrResponse(w, c, ErrInternal)
		return
	}

	utils.StatusResponse(w, c)
}

func (h *Handler) buyItem(w http.ResponseWriter, r *http.Request) {
	s, c := time.Now(), http.StatusOK
	const op = "store.buyItem.hdl"
	defer func() {
		metrics.ObserveRequest(time.Since(s), c, op)
	}()

	uidStr, ok := r.Context().Value("uid").(string)
	if !ok {
		c = http.StatusBadRequest
		utils.ErrResponse(w, c, ErrDecodeRequest)
		return
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		c = http.StatusBadRequest
		utils.ErrResponse(w, c, ErrDecodeRequest)
		return
	}

	item := strings.TrimPrefix(r.URL.Path, "/api/buy/")
	if item == "" {
		c = http.StatusBadRequest
		zap.L().Debug(
			"failed to parse item",
			zap.String("op", op),
		)
		utils.ErrResponse(w, c, ErrItemIsRequired)
		return
	}

	err = h.ctrl.BuyItem(r.Context(), uid, item)
	if err != nil {
		c = http.StatusInternalServerError
		utils.ErrResponse(w, c, ErrInternal)
		return
	}
	utils.StatusResponse(w, c)
}
