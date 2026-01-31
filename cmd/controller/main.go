package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/devalv/leshy-controller/internal/bootstrap"
	"github.com/devalv/leshy-controller/internal/config"
	"github.com/rs/zerolog/log"
)

func main() {
	cfg, err := config.NewConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to read config")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt, syscall.SIGSEGV)
	defer cancel()

	application, err := bootstrap.New(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to bootstrap app") //nolint
	}

	if err := application.Run(ctx); err != nil {
		log.Fatal().Err(err).Msg("application stopped with error")
	}
}
