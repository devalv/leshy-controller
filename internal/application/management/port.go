package management

import "context"

// UseCase is an application contract for management settings.
type UseCase interface {
	SaveSettings(ctx context.Context, settings Settings) (StoredSettings, error)
	GetSettings(ctx context.Context) (StoredSettings, error)
}

// Repository is a storage contract for management settings.
type Repository interface {
	SaveSettings(ctx context.Context, settings Settings) (StoredSettings, error)
	LoadSettings(ctx context.Context) (StoredSettings, error)
}
