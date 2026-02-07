package management

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type repositoryStub struct {
	saveCalls    int
	loadCalls    int
	saved        Settings
	saveFn       func(ctx context.Context, settings Settings) (StoredSettings, error)
	loadSettings StoredSettings
	loadErr      error
}

func (s *repositoryStub) SaveSettings(ctx context.Context, settings Settings) (StoredSettings, error) {
	s.saveCalls++
	s.saved = settings
	if s.saveFn != nil {
		return s.saveFn(ctx, settings)
	}

	return StoredSettings{
		Settings:  settings,
		UpdatedAt: time.Unix(1, 0).UTC(),
	}, nil
}

func (s *repositoryStub) LoadSettings(context.Context) (StoredSettings, error) {
	s.loadCalls++
	if s.loadErr != nil {
		return StoredSettings{}, s.loadErr
	}

	return s.loadSettings, nil
}

func TestServiceSaveSettings(t *testing.T) {
	t.Parallel()

	iface := getUpInterface(t)
	repositoryErr := errors.New("save failed")

	tests := []struct {
		name           string
		input          Settings
		repoSaveFn     func(ctx context.Context, settings Settings) (StoredSettings, error)
		wantErr        error
		wantCalls      int
		wantNormalized Settings
	}{
		{
			name: "empty token",
			input: Settings{
				Token:             "",
				GuardedPortsRange: "1024-2048",
				Iface:             iface,
			},
			wantErr:   ErrInvalidToken,
			wantCalls: 0,
		},
		{
			name: "invalid guarded ports range",
			input: Settings{
				Token:             "abc",
				GuardedPortsRange: "1024 - 2048",
				Iface:             iface,
			},
			wantErr:   ErrInvalidGuardedPortsRange,
			wantCalls: 0,
		},
		{
			name: "invalid interface",
			input: Settings{
				Token:             "abc",
				GuardedPortsRange: "1024-2048",
				Iface:             "this-interface-does-not-exist",
			},
			wantErr:   ErrInvalidIface,
			wantCalls: 0,
		},
		{
			name: "repository returns error",
			input: Settings{
				Token:             "abc",
				GuardedPortsRange: "1024-2048",
				Iface:             iface,
			},
			repoSaveFn: func(context.Context, Settings) (StoredSettings, error) {
				return StoredSettings{}, repositoryErr
			},
			wantErr:   repositoryErr,
			wantCalls: 1,
		},
		{
			name: "success",
			input: Settings{
				Token:             "  abc  ",
				GuardedPortsRange: "1024-2048",
				Iface:             " " + iface + " ",
			},
			wantCalls: 1,
			wantNormalized: Settings{
				Token:             "abc",
				GuardedPortsRange: "1024-2048",
				Iface:             iface,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &repositoryStub{saveFn: tt.repoSaveFn}
			service := New(stub)

			_, err := service.SaveSettings(context.Background(), tt.input)
			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if stub.saveCalls != tt.wantCalls {
				t.Fatalf("repository save calls = %d, want %d", stub.saveCalls, tt.wantCalls)
			}

			if tt.wantCalls > 0 && tt.wantNormalized != (Settings{}) && stub.saved != tt.wantNormalized {
				t.Fatalf("saved settings = %+v, want %+v", stub.saved, tt.wantNormalized)
			}
		})
	}
}

func TestServiceGetSettings(t *testing.T) {
	t.Parallel()

	repositoryErr := errors.New("load failed")

	tests := []struct {
		name        string
		stub        repositoryStub
		wantErr     error
		wantLoadCnt int
	}{
		{
			name:        "settings not found",
			stub:        repositoryStub{loadErr: ErrSettingsNotFound},
			wantErr:     ErrSettingsNotFound,
			wantLoadCnt: 1,
		},
		{
			name:        "repository error",
			stub:        repositoryStub{loadErr: repositoryErr},
			wantErr:     repositoryErr,
			wantLoadCnt: 1,
		},
		{
			name: "success",
			stub: repositoryStub{loadSettings: StoredSettings{
				Settings: Settings{
					Token:             "token",
					GuardedPortsRange: "3389-3391",
					Iface:             "eth0",
				},
				UpdatedAt: time.Unix(1700000000, 0).UTC(),
			}},
			wantLoadCnt: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := New(&tt.stub)
			stored, err := service.GetSettings(context.Background())
			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.stub.loadCalls != tt.wantLoadCnt {
				t.Fatalf("repository load calls = %d, want %d", tt.stub.loadCalls, tt.wantLoadCnt)
			}

			if tt.wantErr == nil && stored != tt.stub.loadSettings {
				t.Fatalf("stored settings = %+v, want %+v", stored, tt.stub.loadSettings)
			}
		})
	}
}

func getUpInterface(t *testing.T) string {
	t.Helper()

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("net.Interfaces() failed: %v", err)
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 {
			return iface.Name
		}
	}

	t.Fatal("no active network interface found")

	return ""
}
