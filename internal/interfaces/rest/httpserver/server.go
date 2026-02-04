package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

type Server struct {
	srv  *http.Server
	name string
}

func New(addr string, handler http.Handler) *Server {
	if handler == nil {
		handler = DefaultNotFoundHandler()
	}

	return &Server{
		name: "http-rest-api:" + addr,
		srv: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 5 * time.Second, //nolint:mnd
		},
	}
}

func (s *Server) Name() string { return s.name }

// Start блокируется, пока сервер работает.
// Остановка происходит извне: оркестратор вызовет Stop(ctx) -> Shutdown().
func (s *Server) Start(ctx context.Context) error {
	// если контекст уже отменён — нет смысла стартовать.
	select {
	case <-ctx.Done():
		return fmt.Errorf("context cancelled: %w", ctx.Err())
	default:
	}

	err := s.srv.ListenAndServe()

	// http.ErrServerClosed — нормальный выход после Shutdown()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}

	return fmt.Errorf("http server listen: %w", err)
}

// Stop делает graceful shutdown, используя ctx (с таймаутом от оркестратора).
func (s *Server) Stop(ctx context.Context) error {
	if err := s.srv.Shutdown(ctx); err != nil {
		// Если graceful не успел — можно принудительно закрыть.
		_ = s.srv.Close()

		return fmt.Errorf("http server shutdown: %w", err)
	}

	return nil
}
