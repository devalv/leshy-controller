package management

import "context"

// UseCase is an application contract for management settings.
type UseCase interface {
	SaveSettings(ctx context.Context, settings Settings) (StoredSettings, error)
	GetSettings(ctx context.Context) (StoredSettings, error)
	AuthorizeAllow(ctx context.Context, accessToken string) error
	AuthorizeSettingsBootstrap(ctx context.Context, bootstrapToken string) error
}

// Repository is a storage contract for management settings.
type Repository interface {
	SaveSettings(ctx context.Context, settings Settings) (StoredSettings, error)
	LoadSettings(ctx context.Context) (StoredSettings, error)
}

// Verifier validates JWT access tokens against configured management settings.
type Verifier interface {
	ValidateSettings(ctx context.Context, settings Settings) error
	VerifyAllowToken(ctx context.Context, settings Settings, accessToken string) error
}
