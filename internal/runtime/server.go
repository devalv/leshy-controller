package runtime

import "context"

// Server is an interface for a server. Configuration will be injected via constructor of specific Server.
type Server interface {
	Name() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}
