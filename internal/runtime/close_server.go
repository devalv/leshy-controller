package runtime

import (
	"context"
	"fmt"
)

// CloserServer — "виртуальный" Server для освобождения ресурсов на shutdown.
type CloserServer struct {
	name    string
	closeFn func(context.Context) error
}

func NewCloserServer(name string, closeFn func(context.Context) error) *CloserServer {
	return &CloserServer{
		name:    name,
		closeFn: closeFn,
	}
}

func (s *CloserServer) Name() string { return s.name }

func (s *CloserServer) Start(ctx context.Context) error {
	<-ctx.Done()

	return nil
}

func (s *CloserServer) Stop(ctx context.Context) error {
	if s.closeFn == nil {
		return nil
	}
	if err := s.closeFn(ctx); err != nil {
		return fmt.Errorf("%s close: %w", s.name, err)
	}

	return nil
}
