package filter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var (
	ErrInvalidPort    = errors.New("invalid port")
	ErrPortNotGuarded = errors.New("port is not guarded")
	ErrNotConfigured  = errors.New("filter is not configured")
)

type UseCase interface {
	Allow(ctx context.Context, ip net.IP, port uint16) (expires time.Time, err error)
	Stats(ctx context.Context) (Stats, error)
	BlockAll(ctx context.Context) (FlushResult, error)
}

type Options struct {
	Window time.Duration
	Debug  bool
	Now    func() time.Time
}

type Service struct {
	mu      sync.RWMutex
	backend Backend
	window  time.Duration
	debug   bool
	now     func() time.Time
}

func New(backend Backend, opts Options) *Service {
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &Service{
		backend: backend,
		window:  opts.Window,
		debug:   opts.Debug,
		now:     now,
	}
}

// ConfigureRuntime replaces backend and window used by Allow/Stats at runtime.
func (s *Service) ConfigureRuntime(backend Backend, window time.Duration) error {
	if backend == nil {
		return errors.New("backend is nil")
	}
	if window <= 0 {
		return errors.New("window must be greater than zero")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.backend = backend
	s.window = window

	return nil
}

func (s *Service) Allow(ctx context.Context, ip net.IP, port uint16) (time.Time, error) {
	if port == 0 {
		return time.Time{}, ErrInvalidPort
	}

	s.mu.RLock()
	backend := s.backend
	window := s.window
	debug := s.debug
	now := s.now
	s.mu.RUnlock()

	if backend == nil || window <= 0 {
		return time.Time{}, ErrNotConfigured
	}

	guarded, err := backend.IsPortGuarded(ctx, port)
	if err != nil {
		return time.Time{}, fmt.Errorf("IsPortGuarded err: %w", err)
	}
	if !guarded {
		return time.Time{}, ErrPortNotGuarded
	}

	if err := backend.InsertPending(ctx, ip, port, window); err != nil {
		return time.Time{}, fmt.Errorf("InsertPending err: %w", err)
	}

	if debug {
		// дополнительная валидация через bpftool
		_ = backend.VerifyPending(ctx, ip, port)
	}

	return now().Add(window), nil
}

func (s *Service) Stats(ctx context.Context) (Stats, error) {
	s.mu.RLock()
	backend := s.backend
	s.mu.RUnlock()

	if backend == nil {
		return Stats{}, ErrNotConfigured
	}

	c, err := backend.Stats(ctx)
	if err != nil {
		return Stats{}, fmt.Errorf("backend stats err: %w", err)
	}

	total := c.Allowed + c.Dropped
	var allowRate, dropRate float64
	if total > 0 {
		allowRate = float64(c.Allowed) / float64(total) * 100 //nolint:mnd
		dropRate = float64(c.Dropped) / float64(total) * 100  //nolint:mnd
	}

	return Stats{
		Counters:         c,
		AllowRatePercent: allowRate,
		DropRatePercent:  dropRate,
	}, nil
}

// BlockAll clears all runtime allow-related entries previously created via Allow.
func (s *Service) BlockAll(ctx context.Context) (FlushResult, error) {
	s.mu.RLock()
	backend := s.backend
	s.mu.RUnlock()

	if backend == nil {
		return FlushResult{}, ErrNotConfigured
	}

	result, err := backend.FlushAuthorizations(ctx)
	if err != nil {
		return FlushResult{}, fmt.Errorf("FlushAuthorizations err: %w", err)
	}

	return result, nil
}
