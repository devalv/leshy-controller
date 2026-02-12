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
	FlushAuthorizations(ctx context.Context) (FlushResult, error)

	// работает только в режиме отладки
	VerifyPending(ctx context.Context, ip net.IP, port uint16) error
}

// RuntimeConfigurator updates filter runtime dependencies without recreating use case.
type RuntimeConfigurator interface {
	ConfigureRuntime(backend Backend, window time.Duration) error
}
