package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const createSchemaMigrationsTableSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	applied_at_unix INTEGER NOT NULL
);
`

type Runner struct {
	db         *sql.DB
	migrations []Migration
}

func NewRunner(db *sql.DB, migrations []Migration) (*Runner, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}

	return &Runner{
		db:         db,
		migrations: migrations,
	}, nil
}

func NewEmbeddedRunner(db *sql.DB) (*Runner, error) {
	embedded, err := Embedded()
	if err != nil {
		return nil, fmt.Errorf("load embedded migrations: %w", err)
	}

	runner, err := NewRunner(db, embedded)
	if err != nil {
		return nil, fmt.Errorf("create migrations runner: %w", err)
	}

	return runner, nil
}

// Up applies pending migrations in ascending version order.
func (r *Runner) Up(ctx context.Context) error {
	if err := r.ensureSchemaTable(ctx); err != nil {
		return fmt.Errorf("ensure schema_migrations table: %w", err)
	}

	applied, err := r.loadAppliedVersions(ctx)
	if err != nil {
		return fmt.Errorf("load applied migration versions: %w", err)
	}

	for _, migration := range r.migrations {
		if applied[migration.Version] {
			continue
		}

		if err := r.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("apply migration %d_%s: %w", migration.Version, migration.Name, err)
		}
	}

	return nil
}

func (r *Runner) ensureSchemaTable(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, createSchemaMigrationsTableSQL); err != nil {
		return fmt.Errorf("create schema_migrations table: %w", err)
	}

	return nil
}

func (r *Runner) loadAppliedVersions(ctx context.Context) (map[int]bool, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT version FROM schema_migrations;")
	if err != nil {
		return nil, fmt.Errorf("query schema_migrations: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()

	applied := make(map[int]bool)
	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, fmt.Errorf("scan migration version: %w", err)
		}

		applied[version] = true
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate schema_migrations rows: %w", err)
	}

	return applied, nil
}

func (r *Runner) applyMigration(ctx context.Context, migration Migration) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}

	if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("rollback migration transaction: %w", rollbackErr)
		}

		return fmt.Errorf("execute migration SQL: %w", err)
	}

	const insertMigrationSQL = `
INSERT INTO schema_migrations (version, name, applied_at_unix)
VALUES (?, ?, CAST(strftime('%s', 'now') AS INTEGER));
`

	if _, err := tx.ExecContext(ctx, insertMigrationSQL, migration.Version, migration.Name); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("rollback migration transaction: %w", rollbackErr)
		}

		return fmt.Errorf("insert migration row: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration transaction: %w", err)
	}

	return nil
}
