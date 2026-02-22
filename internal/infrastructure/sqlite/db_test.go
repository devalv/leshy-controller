package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestOpen(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "empty path",
			path:    "",
			wantErr: true,
		},
		{
			name:    "create db file in nested directory",
			path:    filepath.Join(t.TempDir(), "nested", "management.db"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			db, err := Open(context.Background(), tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			t.Cleanup(func() {
				if closeErr := db.Close(); closeErr != nil {
					t.Fatalf("close db: %v", closeErr)
				}
			})

			if _, statErr := os.Stat(tt.path); statErr != nil {
				t.Fatalf("db file was not created: %v", statErr)
			}
		})
	}
}
