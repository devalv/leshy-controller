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
	// errgroup используется для ожидания завершения всех горутин, на случай нескольких серверов
	g, runCtx := errgroup.WithContext(ctx)

	for _, srv := range a.servers {
		s := srv
		g.Go(func() error {
			log.Info().Msgf("starting %s", s.Name())
			if err := s.Start(runCtx); err != nil {
				return fmt.Errorf("failed to start %s: %w", s.Name(), err)
			}
			log.Info().Msgf("%s stopped", s.Name())

			return nil
		})
	}

	<-ctx.Done()

	stopCtx, cancel := context.WithTimeout(context.Background(), a.opts.ShutdownTimeout)
	defer cancel()

	var stopErr error
	for _, srv := range a.servers {
		log.Info().Msgf("stopping %s", srv.Name())
		if err := srv.Stop(stopCtx); err != nil { //nolint:contextcheck
			log.Debug().Err(err).Msgf("failed to stop %s", srv.Name())
			stopErr = errors.Join(stopErr, err)
		}
	}

	runErr := g.Wait()

	return errors.Join(runErr, stopErr)
}
