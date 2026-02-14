package management

import "context"

// UseCase — это контракт приложения для настроек управления.
type UseCase interface {
	SaveSettings(ctx context.Context, settings Settings) (StoredSettings, error)
	UpdateSettings(ctx context.Context, settings Settings) (StoredSettings, error)
	GetSettings(ctx context.Context) (StoredSettings, error)
	RuntimeStatus(ctx context.Context) RuntimeStatus
	AuthorizeAllow(ctx context.Context, accessToken string) error
	AuthorizeSettingsBootstrap(ctx context.Context, bootstrapToken string) error
}

// Repository — это контракт хранилища для настроек управления.
type Repository interface {
	SaveSettings(ctx context.Context, settings Settings) (StoredSettings, error)
	LoadSettings(ctx context.Context) (StoredSettings, error)
}

// Verifier проверяет JWT-токены доступа на соответствие настроек управления.
type Verifier interface {
	ValidateSettings(ctx context.Context, settings Settings) error
	VerifyAccessToken(ctx context.Context, settings Settings, accessToken string) error
}

// RuntimeApplier применяет runtime настройки к активному процессу.
type RuntimeApplier interface {
	Apply(ctx context.Context, settings Settings) error
}

// RuntimeStatusProvider выводит динамическое состояние runtime приложения.
type RuntimeStatusProvider interface {
	RuntimeStatus(ctx context.Context) RuntimeStatus
}
