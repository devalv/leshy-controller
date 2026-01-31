package filter

import (
	"context"
	"errors"
	"net"
	"time"
)

var (
	ErrInvalidPort    = errors.New("invalid port")
	ErrPortNotGuarded = errors.New("port is not guarded")
)

type UseCase interface {
	Allow(ctx context.Context, ip net.IP, port uint16) (expires time.Time, err error)
	Stats(ctx context.Context) (Stats, error)
}

type Options struct {
	Window time.Duration
	Debug  bool
	Now    func() time.Time
}

type Service struct {
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

func (s *Service) Allow(ctx context.Context, ip net.IP, port uint16) (time.Time, error) {
	if port == 0 {
		return time.Time{}, ErrInvalidPort
	}

	guarded, err := s.backend.IsPortGuarded(ctx, port)
	if err != nil {
		return time.Time{}, err //nolint
	}
	if !guarded {
		return time.Time{}, ErrPortNotGuarded
	}

	if err := s.backend.InsertPending(ctx, ip, port, s.window); err != nil {
		return time.Time{}, err //nolint
	}

	if s.debug {
		// Debug не должен ломать основной сценарий
		_ = s.backend.VerifyPending(ctx, ip, port)
	}

	return s.now().Add(s.window), nil
}

func (s *Service) Stats(ctx context.Context) (Stats, error) {
	c, err := s.backend.Stats(ctx)
	if err != nil {
		return Stats{}, err //nolint
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
