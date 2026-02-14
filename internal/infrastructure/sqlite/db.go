package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const (
	sqliteDirPermission  = 0o750
	sqliteFilePermission = 0o600
)

// Open обеспечивает работу SQLite БД.
func Open(ctx context.Context, dbPath string) (*sql.DB, error) {
	path := strings.TrimSpace(dbPath)
	if path == "" {
		return nil, errors.New("sqlite db path cannot be empty")
	}

	if err := ensureParentDirectory(path); err != nil {
		return nil, fmt.Errorf("prepare sqlite db directory: %w", err)
	}

	if err := ensureDBFile(path); err != nil {
		return nil, fmt.Errorf("prepare sqlite db file: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()

		return nil, fmt.Errorf("ping sqlite db: %w", err)
	}

	if _, err := db.ExecContext(ctx, "PRAGMA foreign_keys = ON;"); err != nil {
		_ = db.Close()

		return nil, fmt.Errorf("enable sqlite foreign keys: %w", err)
	}

	return db, nil
}

func ensureParentDirectory(dbPath string) error {
	dir := filepath.Dir(dbPath)
	if dir == "." || dir == "" {
		return nil
	}

	if err := os.MkdirAll(dir, sqliteDirPermission); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	return nil
}

func ensureDBFile(dbPath string) error {
	// #nosec G304 -- путь берется из проверенной конфигурации времени выполнения и должен оставаться динамическим.
	file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, sqliteFilePermission)
	if err != nil {
		return fmt.Errorf("open db file %s: %w", dbPath, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close db file %s: %w", dbPath, err)
	}

	return nil
}
