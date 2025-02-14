package main

import (
	"context"
	"fmt"
	"github.com/JMURv/avito/internal/auth"
	"github.com/JMURv/avito/internal/config"
	"github.com/JMURv/avito/internal/ctrl"
	hdl "github.com/JMURv/avito/internal/hdl/http"
	"github.com/JMURv/avito/internal/observability/metrics/prometheus"
	"github.com/JMURv/avito/internal/observability/tracing/jaeger"
	"github.com/JMURv/avito/internal/repo/db"
	"go.uber.org/zap"
	"os"
	"os/signal"
	"syscall"
)

const configPath = "configs/local.config.yaml"

func mustRegisterLogger(mode string) {
	switch mode {
	case "prod":
		zap.ReplaceGlobals(zap.Must(zap.NewProduction()))
	case "dev":
		zap.ReplaceGlobals(zap.Must(zap.NewDevelopment()))
	}
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			zap.L().Panic("panic occurred", zap.Any("error", err))
			os.Exit(1)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf := config.MustLoad(configPath)
	mustRegisterLogger(conf.Server.Mode)

	go prometheus.New(conf.Server.Port + 5).Start(ctx)
	go jaeger.Start(ctx, conf.ServiceName, conf.Jaeger)

	au := auth.New(conf.Secret)
	repo := db.New(conf.DB)
	svc := ctrl.New(au, repo)
	h := hdl.New(au, svc)

	zap.L().Info(
		fmt.Sprintf(
			"Starting server on %v://%v:%v",
			conf.Server.Scheme,
			conf.Server.Domain,
			conf.Server.Port,
		),
	)
	go h.Start(conf.Server.Port)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-c

	zap.L().Info("Shutting down gracefully...")
	if err := h.Close(ctx); err != nil {
		zap.L().Warn("Error closing handler", zap.Error(err))
	}

	if err := repo.Close(); err != nil {
		zap.L().Warn("Error closing repository", zap.Error(err))
	}

	os.Exit(0)
}
