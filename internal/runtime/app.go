package runtime

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
)

type Options struct {
	ShutdownTimeout time.Duration
}

// Application выполняет роль Оркестратора для списка серверов.
type Application struct {
	opts    Options
	servers []Server
}

func NewApplication(opts Options, servers ...Server) *Application {
	// дефолты
	if opts.ShutdownTimeout <= 0 {
		opts.ShutdownTimeout = 10 * time.Second //nolint:mnd
	}

	return &Application{opts: opts, servers: servers}
}

// Run starts the application and waits for it to finish.
func (a *Application) Run(ctx context.Context) error {
	g, runCtx := errgroup.WithContext(ctx)

	for _, srv := range a.servers {
		s := srv
		g.Go(func() error {
			log.Info().Msgf("starting %s", s.Name())
			if err := s.Start(runCtx); err != nil {
				return fmt.Errorf("%s: %w", s.Name(), err)
			}
			log.Info().Msgf("%s stopped", s.Name())

			return nil
		})
	}

	// ждём либо сигнал/отмену сверху, либо падение/завершение одной из горутин (runCtx)
	<-runCtx.Done()

	// всегда пытаемся остановить сервера (даже если кто-то упал)
	stopCtx, cancel := context.WithTimeout(context.Background(), a.opts.ShutdownTimeout)
	defer cancel()

	var stopErr error
	for _, srv := range a.servers {
		log.Info().Msgf("stopping %s", srv.Name())
		if err := srv.Stop(stopCtx); err != nil { //nolint:contextcheck
			// если таймаут истёк — это обычно ожидаемо: можно оставить как warn/debug.
			log.Debug().Err(err).Msgf("failed to stop %s", srv.Name())
			stopErr = errors.Join(stopErr, fmt.Errorf("%s: %w", srv.Name(), err))
		}
	}

	runErr := g.Wait()

	// если остановка инициирована внешним ctx (SIGTERM/Interrupt) и runErr=nil — это штатное завершение.
	// возвращаем только stopErr (если он есть).
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return stopErr
	}

	return errors.Join(runErr, stopErr)
}
