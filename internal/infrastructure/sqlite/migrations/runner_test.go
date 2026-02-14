package migrations

import (
	"context"
	"path/filepath"
	"testing"

	sqliteinfra "github.com/devalv/leshy-controller/internal/infrastructure/sqlite"
)

func TestEmbedded(t *testing.T) {
	t.Parallel()

	embeddedMigrations, err := Embedded()
	if err != nil {
		t.Fatalf("embedded migrations load failed: %v", err)
	}
	if len(embeddedMigrations) == 0 {
		t.Fatal("expected at least one migration")
	}

	for i := 1; i < len(embeddedMigrations); i++ {
		if embeddedMigrations[i].Version <= embeddedMigrations[i-1].Version {
			t.Fatalf(
				"migrations are not sorted by version: %d <= %d",
				embeddedMigrations[i].Version,
				embeddedMigrations[i-1].Version,
			)
		}
	}
}

func TestRunnerUpIsIdempotent(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "management.db")
	db, err := sqliteinfra.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := db.Close(); closeErr != nil {
			t.Fatalf("close db: %v", closeErr)
		}
	})

	runner, err := NewEmbeddedRunner(db)
	if err != nil {
		t.Fatalf("create migration runner: %v", err)
	}

	if err := runner.Up(context.Background()); err != nil {
		t.Fatalf("first migration run failed: %v", err)
	}
	if err := runner.Up(context.Background()); err != nil {
		t.Fatalf("second migration run failed: %v", err)
	}
}
