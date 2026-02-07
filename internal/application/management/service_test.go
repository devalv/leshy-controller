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

type verifierStub struct {
	validateCalls int
	verifyCalls   int
	validateFn    func(ctx context.Context, settings Settings) error
	verifyFn      func(ctx context.Context, settings Settings, token string) error
}

func (s *verifierStub) ValidateSettings(ctx context.Context, settings Settings) error {
	s.validateCalls++
	if s.validateFn == nil {
		return nil
	}

	return s.validateFn(ctx, settings)
}

func (s *verifierStub) VerifyAllowToken(ctx context.Context, settings Settings, token string) error {
	s.verifyCalls++
	if s.verifyFn == nil {
		return nil
	}

	return s.verifyFn(ctx, settings, token)
}

func TestServiceSaveSettings(t *testing.T) {
	t.Parallel()

	iface := getUpInterface(t)
	repositoryErr := errors.New("save failed")
	verifierErr := errors.New("jwks lookup failed")

	tests := []struct {
		name           string
		input          Settings
		repoSaveFn     func(ctx context.Context, settings Settings) (StoredSettings, error)
		verifierFn     func(ctx context.Context, settings Settings) error
		wantErr        error
		wantSaveCalls  int
		wantCheckCalls int
		wantNormalized Settings
	}{
		{
			name: "empty issuer",
			input: Settings{
				Issuer:            "",
				Audience:          "leshy-controller",
				JWKSURL:           "https://auth.example.com/jwks.json",
				RequiredScope:     "allow:write",
				GuardedPortsRange: "1024-2048",
				Iface:             iface,
			},
			wantErr:        ErrInvalidIssuer,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
		},
		{
			name: "invalid audience",
			input: Settings{
				Issuer:            "https://auth.example.com",
				Audience:          "",
				JWKSURL:           "https://auth.example.com/jwks.json",
				RequiredScope:     "allow:write",
				GuardedPortsRange: "1024-2048",
				Iface:             iface,
			},
			wantErr:        ErrInvalidAudience,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
		},
		{
			name: "invalid jwks URL",
			input: Settings{
				Issuer:            "https://auth.example.com",
				Audience:          "leshy-controller",
				JWKSURL:           "http://auth.example.com/jwks.json",
				RequiredScope:     "allow:write",
				GuardedPortsRange: "1024-2048",
				Iface:             iface,
			},
			wantErr:        ErrInvalidJWKSURL,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
		},
		{
			name: "invalid required scope",
			input: Settings{
				Issuer:            "https://auth.example.com",
				Audience:          "leshy-controller",
				JWKSURL:           "https://auth.example.com/jwks.json",
				RequiredScope:     "allow: write",
				GuardedPortsRange: "1024-2048",
				Iface:             iface,
			},
			wantErr:        ErrInvalidRequiredScope,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
		},
		{
			name: "invalid guarded ports range",
			input: Settings{
				Issuer:            "https://auth.example.com",
				Audience:          "leshy-controller",
				JWKSURL:           "https://auth.example.com/jwks.json",
				RequiredScope:     "allow:write",
				GuardedPortsRange: "1024 - 2048",
				Iface:             iface,
			},
			wantErr:        ErrInvalidGuardedPortsRange,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
		},
		{
			name: "invalid interface",
			input: Settings{
				Issuer:            "https://auth.example.com",
				Audience:          "leshy-controller",
				JWKSURL:           "https://auth.example.com/jwks.json",
				RequiredScope:     "allow:write",
				GuardedPortsRange: "1024-2048",
				Iface:             "this-interface-does-not-exist",
			},
			wantErr:        ErrInvalidIface,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
		},
		{
			name: "verifier validation fails",
			input: Settings{
				Issuer:            "https://auth.example.com",
				Audience:          "leshy-controller",
				JWKSURL:           "https://auth.example.com/jwks.json",
				RequiredScope:     "allow:write",
				GuardedPortsRange: "1024-2048",
				Iface:             iface,
			},
			verifierFn: func(context.Context, Settings) error {
				return verifierErr
			},
			wantErr:        ErrInvalidJWKSURL,
			wantSaveCalls:  0,
			wantCheckCalls: 1,
		},
		{
			name: "repository returns error",
			input: Settings{
				Issuer:            "https://auth.example.com",
				Audience:          "leshy-controller",
				JWKSURL:           "https://auth.example.com/jwks.json",
				RequiredScope:     "allow:write",
				GuardedPortsRange: "1024-2048",
				Iface:             iface,
			},
			repoSaveFn: func(context.Context, Settings) (StoredSettings, error) {
				return StoredSettings{}, repositoryErr
			},
			wantErr:        repositoryErr,
			wantSaveCalls:  1,
			wantCheckCalls: 1,
		},
		{
			name: "success with normalization",
			input: Settings{
				Issuer:            "  https://auth.example.com  ",
				Audience:          "  leshy-controller ",
				JWKSURL:           "  https://auth.example.com/jwks.json ",
				RequiredScope:     " allow:write ",
				GuardedPortsRange: "1024-2048",
				Iface:             " " + iface + " ",
			},
			wantSaveCalls:  1,
			wantCheckCalls: 1,
			wantNormalized: Settings{
				Issuer:            "https://auth.example.com",
				Audience:          "leshy-controller",
				JWKSURL:           "https://auth.example.com/jwks.json",
				RequiredScope:     "allow:write",
				GuardedPortsRange: "1024-2048",
				Iface:             iface,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			repo := &repositoryStub{saveFn: tt.repoSaveFn}
			verifier := &verifierStub{validateFn: tt.verifierFn}
			service := New(repo, verifier, Options{})

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

			if repo.saveCalls != tt.wantSaveCalls {
				t.Fatalf("repository save calls = %d, want %d", repo.saveCalls, tt.wantSaveCalls)
			}
			if verifier.validateCalls != tt.wantCheckCalls {
				t.Fatalf("verifier validate calls = %d, want %d", verifier.validateCalls, tt.wantCheckCalls)
			}
			if tt.wantSaveCalls > 0 && tt.wantNormalized != (Settings{}) && repo.saved != tt.wantNormalized {
				t.Fatalf("saved settings = %+v, want %+v", repo.saved, tt.wantNormalized)
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
					Issuer:            "https://auth.example.com",
					Audience:          "leshy-controller",
					JWKSURL:           "https://auth.example.com/jwks.json",
					RequiredScope:     "allow:write",
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

			service := New(&tt.stub, &verifierStub{}, Options{})
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

func TestServiceAuthorizeAllow(t *testing.T) {
	t.Parallel()

	repositoryErr := errors.New("load failed")

	tests := []struct {
		name           string
		token          string
		repo           repositoryStub
		verifyFn       func(ctx context.Context, settings Settings, token string) error
		wantErr        error
		wantLoadCalls  int
		wantVerifyCall int
	}{
		{
			name:           "empty token",
			token:          "",
			wantErr:        ErrInvalidAccessToken,
			wantLoadCalls:  0,
			wantVerifyCall: 0,
		},
		{
			name:  "settings not found",
			token: "token",
			repo: repositoryStub{
				loadErr: ErrSettingsNotFound,
			},
			wantErr:        ErrSettingsNotFound,
			wantLoadCalls:  1,
			wantVerifyCall: 0,
		},
		{
			name:  "repository failure",
			token: "token",
			repo: repositoryStub{
				loadErr: repositoryErr,
			},
			wantErr:        repositoryErr,
			wantLoadCalls:  1,
			wantVerifyCall: 0,
		},
		{
			name:  "invalid access token",
			token: "token",
			repo: repositoryStub{
				loadSettings: StoredSettings{
					Settings: Settings{
						Issuer:        "https://auth.example.com",
						Audience:      "leshy-controller",
						JWKSURL:       "https://auth.example.com/jwks.json",
						RequiredScope: "allow:write",
					},
				},
			},
			verifyFn: func(context.Context, Settings, string) error {
				return ErrInvalidAccessToken
			},
			wantErr:        ErrInvalidAccessToken,
			wantLoadCalls:  1,
			wantVerifyCall: 1,
		},
		{
			name:  "authorization unavailable",
			token: "token",
			repo: repositoryStub{
				loadSettings: StoredSettings{
					Settings: Settings{
						Issuer:        "https://auth.example.com",
						Audience:      "leshy-controller",
						JWKSURL:       "https://auth.example.com/jwks.json",
						RequiredScope: "allow:write",
					},
				},
			},
			verifyFn: func(context.Context, Settings, string) error {
				return ErrAuthorizationUnavailable
			},
			wantErr:        ErrAuthorizationUnavailable,
			wantLoadCalls:  1,
			wantVerifyCall: 1,
		},
		{
			name:  "success",
			token: "token",
			repo: repositoryStub{
				loadSettings: StoredSettings{
					Settings: Settings{
						Issuer:        "https://auth.example.com",
						Audience:      "leshy-controller",
						JWKSURL:       "https://auth.example.com/jwks.json",
						RequiredScope: "allow:write",
					},
				},
			},
			wantLoadCalls:  1,
			wantVerifyCall: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			verifier := &verifierStub{verifyFn: tt.verifyFn}
			service := New(&tt.repo, verifier, Options{})

			err := service.AuthorizeAllow(context.Background(), tt.token)
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

			if tt.repo.loadCalls != tt.wantLoadCalls {
				t.Fatalf("repository load calls = %d, want %d", tt.repo.loadCalls, tt.wantLoadCalls)
			}
			if verifier.verifyCalls != tt.wantVerifyCall {
				t.Fatalf("verifier verify calls = %d, want %d", verifier.verifyCalls, tt.wantVerifyCall)
			}
		})
	}
}

func TestServiceAuthorizeSettingsBootstrap(t *testing.T) {
	t.Parallel()

	repositoryErr := errors.New("load failed")
	settings := StoredSettings{
		Settings: Settings{
			Issuer:        "https://auth.example.com",
			Audience:      "leshy-controller",
			JWKSURL:       "https://auth.example.com/jwks.json",
			RequiredScope: "allow:write",
		},
		UpdatedAt: time.Unix(1700000000, 0).UTC(),
	}

	tests := []struct {
		name          string
		serviceOpts   Options
		token         string
		repo          repositoryStub
		wantErr       error
		wantLoadCalls int
	}{
		{
			name:        "bootstrap not configured",
			serviceOpts: Options{},
			token:       "secret",
			wantErr:     ErrBootstrapNotConfigured,
		},
		{
			name: "settings already configured",
			serviceOpts: Options{
				BootstrapToken: "secret",
			},
			token: "secret",
			repo: repositoryStub{
				loadSettings: settings,
			},
			wantErr:       ErrBootstrapLocked,
			wantLoadCalls: 1,
		},
		{
			name: "repository failure",
			serviceOpts: Options{
				BootstrapToken: "secret",
			},
			token: "secret",
			repo: repositoryStub{
				loadErr: repositoryErr,
			},
			wantErr:       repositoryErr,
			wantLoadCalls: 1,
		},
		{
			name: "invalid token",
			serviceOpts: Options{
				BootstrapToken: "secret",
			},
			token: "",
			repo: repositoryStub{
				loadErr: ErrSettingsNotFound,
			},
			wantErr:       ErrInvalidBootstrapToken,
			wantLoadCalls: 1,
		},
		{
			name: "wrong token",
			serviceOpts: Options{
				BootstrapToken: "secret",
			},
			token: "bad",
			repo: repositoryStub{
				loadErr: ErrSettingsNotFound,
			},
			wantErr:       ErrInvalidBootstrapToken,
			wantLoadCalls: 1,
		},
		{
			name: "success",
			serviceOpts: Options{
				BootstrapToken: "secret",
			},
			token: "secret",
			repo: repositoryStub{
				loadErr: ErrSettingsNotFound,
			},
			wantLoadCalls: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := New(&tt.repo, &verifierStub{}, tt.serviceOpts)
			err := service.AuthorizeSettingsBootstrap(context.Background(), tt.token)
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

			if tt.repo.loadCalls != tt.wantLoadCalls {
				t.Fatalf("repository load calls = %d, want %d", tt.repo.loadCalls, tt.wantLoadCalls)
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
