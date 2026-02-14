package migrations

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

//go:embed sql/*.sql
var sqlMigrationsFS embed.FS

type Migration struct {
	Version int
	Name    string
	SQL     string
}

const migrationFileNameParts = 2

// Embedded возвращает список SQL-миграций, отсортированных по версии.
func Embedded() ([]Migration, error) {
	entries, err := fs.ReadDir(sqlMigrationsFS, "sql")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations directory: %w", err)
	}

	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		version, name, err := parseMigrationFileName(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("parse migration filename %s: %w", entry.Name(), err)
		}

		content, err := fs.ReadFile(sqlMigrationsFS, filepath.Join("sql", entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read migration file %s: %w", entry.Name(), err)
		}

		migrations = append(migrations, Migration{
			Version: version,
			Name:    name,
			SQL:     string(content),
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	for i := 1; i < len(migrations); i++ {
		if migrations[i].Version == migrations[i-1].Version {
			return nil, fmt.Errorf("duplicate migration version: %d", migrations[i].Version)
		}
	}

	return migrations, nil
}

func parseMigrationFileName(fileName string) (int, string, error) {
	base := strings.TrimSuffix(fileName, filepath.Ext(fileName))
	parts := strings.SplitN(base, "_", migrationFileNameParts)
	if len(parts) != migrationFileNameParts {
		return 0, "", fmt.Errorf("invalid migration file name format: %s", fileName)
	}

	version, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, "", fmt.Errorf("invalid migration version %s: %w", parts[0], err)
	}

	name := strings.TrimSpace(parts[1])
	if name == "" {
		return 0, "", fmt.Errorf("migration name is empty in file: %s", fileName)
	}

	return version, name, nil
}
