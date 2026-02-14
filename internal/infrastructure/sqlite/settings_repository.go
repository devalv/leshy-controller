package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/devalv/leshy-controller/internal/application/management"
)

// ManagementSettingsRepository обеспечивает SQLite-backed для хранения настроек приложения.
type ManagementSettingsRepository struct {
	db *sql.DB
}

// NewManagementSettingsRepository создаёт Repository, поддерживаемый sql.DB.
func NewManagementSettingsRepository(db *sql.DB) (*ManagementSettingsRepository, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	return &ManagementSettingsRepository{db: db}, nil
}

// SaveSettings сохраняет настройки в БД.
func (r *ManagementSettingsRepository) SaveSettings(
	ctx context.Context,
	settings management.Settings,
) (management.StoredSettings, error) {
	const saveSQL = `
INSERT INTO management_settings (
	id,
	issuer,
	audience,
	jwks_url,
	required_scope,
	guarded_ports_range,
	iface,
	handshake_window_sec,
	updated_at_unix
)
VALUES (1, ?, ?, ?, ?, ?, ?, ?, CAST(strftime('%s', 'now') AS INTEGER))
ON CONFLICT(id) DO UPDATE SET
	issuer = excluded.issuer,
	audience = excluded.audience,
	jwks_url = excluded.jwks_url,
	required_scope = excluded.required_scope,
	guarded_ports_range = excluded.guarded_ports_range,
	iface = excluded.iface,
	handshake_window_sec = excluded.handshake_window_sec,
	updated_at_unix = CAST(strftime('%s', 'now') AS INTEGER);
`

	if _, err := r.db.ExecContext(
		ctx,
		saveSQL,
		settings.Issuer,
		settings.Audience,
		settings.JWKSURL,
		settings.RequiredScope,
		settings.GuardedPortsRange,
		settings.Iface,
		settings.HandshakeWindowSec,
	); err != nil {
		return management.StoredSettings{}, fmt.Errorf("upsert management settings: %w", err)
	}

	stored, err := r.LoadSettings(ctx)
	if err != nil {
		return management.StoredSettings{}, fmt.Errorf("load saved management settings: %w", err)
	}

	return stored, nil
}

// LoadSettings читает настройки хранящиеся в БД.
func (r *ManagementSettingsRepository) LoadSettings(ctx context.Context) (management.StoredSettings, error) {
	const loadSQL = `
SELECT issuer, audience, jwks_url, required_scope, guarded_ports_range, iface, handshake_window_sec, updated_at_unix
FROM management_settings
WHERE id = 1;
`

	var (
		issuer             string
		audience           string
		jwksURL            string
		requiredScope      string
		guardedPortsRange  string
		iface              string
		handshakeWindowSec int
		updatedAtUnix      int64
	)

	if err := r.db.QueryRowContext(ctx, loadSQL).Scan(
		&issuer,
		&audience,
		&jwksURL,
		&requiredScope,
		&guardedPortsRange,
		&iface,
		&handshakeWindowSec,
		&updatedAtUnix,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return management.StoredSettings{}, management.ErrSettingsNotFound
		}

		return management.StoredSettings{}, fmt.Errorf("query management settings: %w", err)
	}

	return management.StoredSettings{
		Settings: management.Settings{
			Issuer:             issuer,
			Audience:           audience,
			JWKSURL:            jwksURL,
			RequiredScope:      requiredScope,
			GuardedPortsRange:  guardedPortsRange,
			Iface:              iface,
			HandshakeWindowSec: handshakeWindowSec,
		},
		UpdatedAt: time.Unix(updatedAtUnix, 0).UTC(),
	}, nil
}

// Close высвобождает ресурсы Repository.
func (r *ManagementSettingsRepository) Close() error {
	if r == nil || r.db == nil {
		return nil
	}

	if err := r.db.Close(); err != nil {
		return fmt.Errorf("close sqlite db: %w", err)
	}

	return nil
}
