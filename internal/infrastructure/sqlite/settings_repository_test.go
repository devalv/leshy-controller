package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/devalv/leshy-controller/internal/application/management"
	sqlitemigrations "github.com/devalv/leshy-controller/internal/infrastructure/sqlite/migrations"
)

func TestManagementSettingsRepositoryLoadSettingsWhenEmpty(t *testing.T) {
	t.Parallel()

	repository := createRepositoryWithMigrations(t)

	_, loadErr := repository.LoadSettings(context.Background())
	if loadErr == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(loadErr, management.ErrSettingsNotFound) {
		t.Fatalf("expected ErrSettingsNotFound, got %v", loadErr)
	}
}

func TestManagementSettingsRepositorySaveSettings(t *testing.T) {
	t.Parallel()

	repository := createRepositoryWithMigrations(t)

	tests := []struct {
		name     string
		settings management.Settings
	}{
		{
			name: "insert initial settings",
			settings: management.Settings{
				Token:             "token-v1",
				GuardedPortsRange: "3389-3391",
				Iface:             "ens18",
			},
		},
		{
			name: "update existing settings",
			settings: management.Settings{
				Token:             "token-v2",
				GuardedPortsRange: "3392-3399",
				Iface:             "ens19",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			stored, saveErr := repository.SaveSettings(context.Background(), tt.settings)
			if saveErr != nil {
				t.Fatalf("save settings: %v", saveErr)
			}

			if stored.Token != tt.settings.Token {
				t.Fatalf("stored token = %q, want %q", stored.Token, tt.settings.Token)
			}
			if stored.GuardedPortsRange != tt.settings.GuardedPortsRange {
				t.Fatalf(
					"stored guarded ports range = %q, want %q",
					stored.GuardedPortsRange,
					tt.settings.GuardedPortsRange,
				)
			}
			if stored.Iface != tt.settings.Iface {
				t.Fatalf("stored iface = %q, want %q", stored.Iface, tt.settings.Iface)
			}
			if stored.UpdatedAt.IsZero() {
				t.Fatal("updated_at should not be zero")
			}

			loaded, loadErr := repository.LoadSettings(context.Background())
			if loadErr != nil {
				t.Fatalf("load settings: %v", loadErr)
			}
			if loaded.Token != tt.settings.Token {
				t.Fatalf("loaded token = %q, want %q", loaded.Token, tt.settings.Token)
			}
		})
	}
}

func createRepositoryWithMigrations(t *testing.T) *ManagementSettingsRepository {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "management.db")
	db, err := Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Fatalf("close db: %v", closeErr)
		}
	})

	migrationRunner, err := sqlitemigrations.NewEmbeddedRunner(db)
	if err != nil {
		t.Fatalf("create migrations runner: %v", err)
	}
	if err := migrationRunner.Up(context.Background()); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	repository, err := NewManagementSettingsRepository(db)
	if err != nil {
		t.Fatalf("create repository: %v", err)
	}

	return repository
}
