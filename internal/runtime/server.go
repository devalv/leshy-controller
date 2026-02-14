package runtime

import "context"

// Server описывает интерфейс server. Конфигурация внедряется через конструктор конкретного сервера.
type Server interface {
	Name() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}
