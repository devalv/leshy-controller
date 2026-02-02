package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/devalv/leshy-controller/internal/bootstrap"
	"github.com/devalv/leshy-controller/internal/config"
	"github.com/rs/zerolog/log"
)

func main() {
	if err := run(); err != nil {
		log.Error().Err(err).Msg("exit")
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.NewConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}
	log.Debug().Msgf("config: %+v", cfg)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt, syscall.SIGSEGV)
	defer cancel()

	application, err := bootstrap.New(ctx, cfg)
	if err != nil {
		return fmt.Errorf("failed to bootstrap application: %w", err)
	}

	if err := application.Run(ctx); err != nil {
		return fmt.Errorf("application run: %w", err)
	}

	return nil
}
