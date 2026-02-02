package filter

import (
	"context"
	"net"
	"time"
)

type Backend interface {
	IsPortGuarded(ctx context.Context, port uint16) (bool, error)
	InsertPending(ctx context.Context, ip net.IP, port uint16, window time.Duration) error
	Stats(ctx context.Context) (Counters, error)

	// Работает только в режиме отладки
	VerifyPending(ctx context.Context, ip net.IP, port uint16) error
}
