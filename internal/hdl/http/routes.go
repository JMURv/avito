package http

import (
	"encoding/json"
	"errors"
	"github.com/JMURv/avito/internal/auth"
	"github.com/JMURv/avito/internal/config"
	"github.com/JMURv/avito/internal/ctrl"
	"github.com/JMURv/avito/internal/dto"
	"github.com/JMURv/avito/internal/hdl"
	"github.com/JMURv/avito/internal/hdl/http/middleware"
	"github.com/JMURv/avito/internal/hdl/http/utils"
	"github.com/JMURv/avito/internal/hdl/validation"
	"github.com/JMURv/avito/internal/model"
	metrics "github.com/JMURv/avito/internal/observability/metrics/prometheus"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net/http"
	"strconv"
	"strings"
	"time"
)

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

	if r.Method != http.MethodPost {
		c = http.StatusMethodNotAllowed
		utils.ErrResponse(w, c, ErrMethodNotAllowed)
		return
	}

	req := &model.User{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		c = http.StatusBadRequest
		zap.L().Debug(
			"failed to decode request",
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, hdl.ErrDecodeRequest)
		return
	}

	if err := validation.AuthReq(req); err != nil {
		c = http.StatusBadRequest
		zap.L().Debug(
			"failed to validate auth request",
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
	} else if err != nil {
		c = http.StatusInternalServerError
		zap.L().Debug(
			hdl.ErrInternal.Error(),
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, hdl.ErrInternal)
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

	if r.Method != http.MethodGet {
		c = http.StatusMethodNotAllowed
		utils.ErrResponse(w, c, ErrMethodNotAllowed)
		return
	}

	uidStr, ok := r.Context().Value("uid").(string)
	if !ok {
		c = http.StatusBadRequest
		zap.L().Error(
			hdl.ErrFailedToGetUUID.Error(),
			zap.String("op", op), zap.Any("uid", r.Context().Value("uid")),
		)
		utils.ErrResponse(w, c, hdl.ErrDecodeRequest)
		return
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		c = http.StatusBadRequest
		zap.L().Error(
			hdl.ErrFailedToParseUUID.Error(),
			zap.String("op", op), zap.String("uid", uidStr),
		)
		utils.ErrResponse(w, c, hdl.ErrDecodeRequest)
		return
	}

	page, err := strconv.ParseInt(r.URL.Query().Get("page"), 10, 64)
	if err != nil {
		page = config.DefaultPage
	}

	size, err := strconv.ParseInt(r.URL.Query().Get("size"), 10, 64)
	if err != nil {
		size = config.DefaultSize
	}

	res, err := h.ctrl.GetInfo(r.Context(), uid, int(page), int(size))
	if err != nil && errors.Is(err, ctrl.ErrNotFound) {
		c = http.StatusNotFound
		utils.ErrResponse(w, c, err)
		return
	} else if err != nil {
		c = http.StatusInternalServerError
		zap.L().Debug(
			hdl.ErrInternal.Error(),
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, hdl.ErrInternal)
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

	if r.Method != http.MethodPost {
		c = http.StatusMethodNotAllowed
		utils.ErrResponse(w, c, ErrMethodNotAllowed)
		return
	}

	uidStr, ok := r.Context().Value("uid").(string)
	if !ok {
		c = http.StatusBadRequest
		zap.L().Error(
			hdl.ErrFailedToGetUUID.Error(),
			zap.String("op", op), zap.Any("uid", r.Context().Value("uid")),
		)
		utils.ErrResponse(w, c, hdl.ErrDecodeRequest)
		return
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		c = http.StatusBadRequest
		zap.L().Error(
			hdl.ErrFailedToParseUUID.Error(),
			zap.String("op", op), zap.String("uid", uidStr),
		)
		utils.ErrResponse(w, c, hdl.ErrDecodeRequest)
		return
	}

	req := &dto.SendCoinRequest{}
	if err = json.NewDecoder(r.Body).Decode(req); err != nil {
		c = http.StatusBadRequest
		zap.L().Debug(
			"failed to decode request",
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, hdl.ErrDecodeRequest)
		return
	}

	if err = validation.SendCoinReq(req); err != nil {
		c = http.StatusBadRequest
		zap.L().Debug(
			"failed to validate request",
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, err)
		return
	}

	err = h.ctrl.SendCoin(r.Context(), uid, req)
	if err != nil {
		c = http.StatusInternalServerError
		zap.L().Debug(
			hdl.ErrInternal.Error(),
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, hdl.ErrInternal)
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

	if r.Method != http.MethodGet {
		c = http.StatusMethodNotAllowed
		utils.ErrResponse(w, c, ErrMethodNotAllowed)
		return
	}

	uidStr, ok := r.Context().Value("uid").(string)
	if !ok {
		c = http.StatusBadRequest
		zap.L().Error(
			hdl.ErrFailedToGetUUID.Error(),
			zap.String("op", op), zap.Any("uid", r.Context().Value("uid")),
		)
		utils.ErrResponse(w, c, hdl.ErrDecodeRequest)
		return
	}

	uid, err := uuid.Parse(uidStr)
	if err != nil {
		c = http.StatusBadRequest
		zap.L().Error(
			hdl.ErrFailedToParseUUID.Error(),
			zap.String("op", op), zap.String("uid", uidStr),
		)
		utils.ErrResponse(w, c, hdl.ErrDecodeRequest)
		return
	}

	item := strings.TrimPrefix(r.URL.Path, "/api/buy/")
	if item == "" {
		c = http.StatusBadRequest
		zap.L().Debug(
			"failed to parse url param",
			zap.String("op", op), zap.String("path", r.URL.Path),
		)
		utils.ErrResponse(w, c, ErrItemIsRequired)
		return
	}

	err = h.ctrl.BuyItem(r.Context(), uid, item)
	if err != nil {
		c = http.StatusInternalServerError
		zap.L().Debug(
			hdl.ErrInternal.Error(),
			zap.String("op", op), zap.Error(err),
		)
		utils.ErrResponse(w, c, hdl.ErrInternal)
		return
	}
	utils.StatusResponse(w, c)
}
