package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/devalv/leshy-controller/internal/application/management"
)

// ManagementSettingsRepository provides SQLite-backed persistence for management settings.
type ManagementSettingsRepository struct {
	db *sql.DB
}

// NewManagementSettingsRepository creates repository backed by sql.DB.
func NewManagementSettingsRepository(db *sql.DB) (*ManagementSettingsRepository, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	return &ManagementSettingsRepository{db: db}, nil
}

// SaveSettings upserts single management settings record.
func (r *ManagementSettingsRepository) SaveSettings(
	ctx context.Context,
	settings management.Settings,
) (management.StoredSettings, error) {
	const saveSQL = `
INSERT INTO management_settings (id, token, guarded_ports_range, iface, updated_at_unix)
VALUES (1, ?, ?, ?, CAST(strftime('%s', 'now') AS INTEGER))
ON CONFLICT(id) DO UPDATE SET
	token = excluded.token,
	guarded_ports_range = excluded.guarded_ports_range,
	iface = excluded.iface,
	updated_at_unix = CAST(strftime('%s', 'now') AS INTEGER);
`

	if _, err := r.db.ExecContext(
		ctx,
		saveSQL,
		settings.Token,
		settings.GuardedPortsRange,
		settings.Iface,
	); err != nil {
		return management.StoredSettings{}, fmt.Errorf("upsert management settings: %w", err)
	}

	stored, err := r.LoadSettings(ctx)
	if err != nil {
		return management.StoredSettings{}, fmt.Errorf("load saved management settings: %w", err)
	}

	return stored, nil
}

// LoadSettings reads stored management settings.
func (r *ManagementSettingsRepository) LoadSettings(ctx context.Context) (management.StoredSettings, error) {
	const loadSQL = `
SELECT token, guarded_ports_range, iface, updated_at_unix
FROM management_settings
WHERE id = 1;
`

	var (
		token             string
		guardedPortsRange string
		iface             string
		updatedAtUnix     int64
	)

	if err := r.db.QueryRowContext(ctx, loadSQL).Scan(
		&token,
		&guardedPortsRange,
		&iface,
		&updatedAtUnix,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return management.StoredSettings{}, management.ErrSettingsNotFound
		}

		return management.StoredSettings{}, fmt.Errorf("query management settings: %w", err)
	}

	return management.StoredSettings{
		Settings: management.Settings{
			Token:             token,
			GuardedPortsRange: guardedPortsRange,
			Iface:             iface,
		},
		UpdatedAt: time.Unix(updatedAtUnix, 0).UTC(),
	}, nil
}

// Close releases repository resources.
func (r *ManagementSettingsRepository) Close() error {
	if r == nil || r.db == nil {
		return nil
	}

	if err := r.db.Close(); err != nil {
		return fmt.Errorf("close sqlite db: %w", err)
	}

	return nil
}
