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

func (s *verifierStub) VerifyAccessToken(ctx context.Context, settings Settings, token string) error {
	s.verifyCalls++
	if s.verifyFn == nil {
		return nil
	}

	return s.verifyFn(ctx, settings, token)
}

type runtimeApplierStub struct {
	applyCalls int
	applyFn    func(ctx context.Context, settings Settings) error
	statusFn   func(ctx context.Context) RuntimeStatus
}

func (s *runtimeApplierStub) Apply(ctx context.Context, settings Settings) error {
	s.applyCalls++
	if s.applyFn == nil {
		return nil
	}

	return s.applyFn(ctx, settings)
}

func (s *runtimeApplierStub) RuntimeStatus(ctx context.Context) RuntimeStatus {
	if s.statusFn == nil {
		return RuntimeStatus{}
	}

	return s.statusFn(ctx)
}

func TestServiceSaveSettings(t *testing.T) {
	t.Parallel()

	iface := getUpInterface(t)
	repositoryErr := errors.New("save failed")
	verifierErr := errors.New("jwks lookup failed")
	runtimeApplyErr := errors.New("runtime apply failed")

	tests := []struct {
		name           string
		input          Settings
		repoSaveFn     func(ctx context.Context, settings Settings) (StoredSettings, error)
		verifierFn     func(ctx context.Context, settings Settings) error
		runtimeApplyFn func(ctx context.Context, settings Settings) error
		runtimeStatus  RuntimeStatus
		wantErr        error
		wantSaveCalls  int
		wantCheckCalls int
		wantApplyCalls int
		wantNormalized Settings
	}{
		{
			name: "empty issuer",
			input: Settings{
				Issuer:             "",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			wantErr:        ErrInvalidIssuer,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "invalid audience",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			wantErr:        ErrInvalidAudience,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "invalid jwks URL",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "http://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			wantErr:        ErrInvalidJWKSURL,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "invalid required scope",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow: write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			wantErr:        ErrInvalidRequiredScope,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "invalid guarded ports range",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024 - 2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			wantErr:        ErrInvalidGuardedPortsRange,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "guarded ports range exceeds max entries",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-3072", // 2049 ports
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			wantErr:        ErrInvalidGuardedPortsRange,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "invalid interface",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              "this-interface-does-not-exist",
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			wantErr:        ErrInvalidIface,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "invalid handshake window",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 0,
				InactiveTimerSec:   300,
			},
			wantErr:        ErrInvalidHandshakeWindow,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "invalid inactive timer",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   0,
			},
			wantErr:        ErrInvalidInactiveTimer,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "verifier validation fails",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			verifierFn: func(context.Context, Settings) error {
				return verifierErr
			},
			wantErr:        ErrInvalidJWKSURL,
			wantSaveCalls:  0,
			wantCheckCalls: 1,
			wantApplyCalls: 0,
		},
		{
			name: "runtime apply returns error",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			runtimeApplyFn: func(context.Context, Settings) error {
				return runtimeApplyErr
			},
			wantErr:        runtimeApplyErr,
			wantSaveCalls:  1,
			wantCheckCalls: 1,
			wantApplyCalls: 1,
		},
		{
			name: "repository returns error",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			repoSaveFn: func(context.Context, Settings) (StoredSettings, error) {
				return StoredSettings{}, repositoryErr
			},
			wantErr:        repositoryErr,
			wantSaveCalls:  1,
			wantCheckCalls: 1,
			wantApplyCalls: 0,
		},
		{
			name: "success with normalization",
			input: Settings{
				Issuer:             "  https://auth.example.com  ",
				Audience:           "  leshy-controller ",
				JWKSURL:            "  https://auth.example.com/jwks.json ",
				RequiredScope:      " allow:write ",
				GuardedPortsRange:  "1024-2048",
				Iface:              " " + iface + " ",
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			wantSaveCalls:  1,
			wantCheckCalls: 1,
			wantApplyCalls: 1,
			runtimeStatus: RuntimeStatus{
				Attached: true,
				Iface:    iface,
			},
			wantNormalized: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			repo := &repositoryStub{saveFn: tt.repoSaveFn}
			verifier := &verifierStub{validateFn: tt.verifierFn}
			applier := &runtimeApplierStub{
				applyFn: tt.runtimeApplyFn,
				statusFn: func(context.Context) RuntimeStatus {
					return tt.runtimeStatus
				},
			}
			service := New(repo, verifier, Options{RuntimeApplier: applier})

			stored, err := service.SaveSettings(context.Background(), tt.input)
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
			if applier.applyCalls != tt.wantApplyCalls {
				t.Fatalf("runtime apply calls = %d, want %d", applier.applyCalls, tt.wantApplyCalls)
			}
			if tt.wantSaveCalls > 0 && tt.wantNormalized != (Settings{}) && repo.saved != tt.wantNormalized {
				t.Fatalf("saved settings = %+v, want %+v", repo.saved, tt.wantNormalized)
			}
			if tt.wantErr == nil && stored.Runtime != tt.runtimeStatus {
				t.Fatalf("stored runtime status = %+v, want %+v", stored.Runtime, tt.runtimeStatus)
			}
		})
	}
}

func TestServiceUpdateSettings(t *testing.T) {
	t.Parallel()

	iface := getUpInterface(t)
	repositoryErr := errors.New("load failed")
	verifierErr := errors.New("jwks lookup failed")
	saveErr := errors.New("save failed")
	runtimeApplyErr := errors.New("runtime apply failed")

	tests := []struct {
		name           string
		input          Settings
		repo           repositoryStub
		verifierFn     func(ctx context.Context, settings Settings) error
		runtimeApplyFn func(ctx context.Context, settings Settings) error
		runtimeStatus  RuntimeStatus
		wantErr        error
		wantLoadCalls  int
		wantSaveCalls  int
		wantCheckCalls int
		wantApplyCalls int
		wantNormalized Settings
	}{
		{
			name: "settings not found",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			repo: repositoryStub{
				loadErr: ErrSettingsNotFound,
			},
			wantErr:        ErrSettingsNotFound,
			wantLoadCalls:  1,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "load failure",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			repo: repositoryStub{
				loadErr: repositoryErr,
			},
			wantErr:        repositoryErr,
			wantLoadCalls:  1,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "invalid audience",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			repo: repositoryStub{
				loadSettings: StoredSettings{
					Settings: Settings{
						Issuer:             "https://auth.example.com",
						Audience:           "leshy-controller",
						JWKSURL:            "https://auth.example.com/jwks.json",
						RequiredScope:      "allow:write",
						GuardedPortsRange:  "1024-2048",
						Iface:              iface,
						HandshakeWindowSec: 600,
						InactiveTimerSec:   300,
					},
				},
			},
			wantErr:        ErrInvalidAudience,
			wantLoadCalls:  1,
			wantSaveCalls:  0,
			wantCheckCalls: 0,
			wantApplyCalls: 0,
		},
		{
			name: "verifier validation fails",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			repo: repositoryStub{
				loadSettings: StoredSettings{
					Settings: Settings{
						Issuer:             "https://auth.example.com",
						Audience:           "leshy-controller",
						JWKSURL:            "https://auth.example.com/jwks.json",
						RequiredScope:      "allow:write",
						GuardedPortsRange:  "1024-2048",
						Iface:              iface,
						HandshakeWindowSec: 600,
						InactiveTimerSec:   300,
					},
				},
			},
			verifierFn: func(context.Context, Settings) error {
				return verifierErr
			},
			wantErr:        ErrInvalidJWKSURL,
			wantLoadCalls:  1,
			wantSaveCalls:  0,
			wantCheckCalls: 1,
			wantApplyCalls: 0,
		},
		{
			name: "save failure",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			repo: repositoryStub{
				loadSettings: StoredSettings{
					Settings: Settings{
						Issuer:             "https://auth.example.com",
						Audience:           "leshy-controller",
						JWKSURL:            "https://auth.example.com/jwks.json",
						RequiredScope:      "allow:write",
						GuardedPortsRange:  "1024-2048",
						Iface:              iface,
						HandshakeWindowSec: 600,
						InactiveTimerSec:   300,
					},
				},
				saveFn: func(context.Context, Settings) (StoredSettings, error) {
					return StoredSettings{}, saveErr
				},
			},
			wantErr:        saveErr,
			wantLoadCalls:  1,
			wantSaveCalls:  1,
			wantCheckCalls: 1,
			wantApplyCalls: 0,
		},
		{
			name: "runtime apply failure",
			input: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			repo: repositoryStub{
				loadSettings: StoredSettings{
					Settings: Settings{
						Issuer:             "https://auth.example.com",
						Audience:           "leshy-controller",
						JWKSURL:            "https://auth.example.com/jwks.json",
						RequiredScope:      "allow:write",
						GuardedPortsRange:  "1024-2048",
						Iface:              iface,
						HandshakeWindowSec: 600,
						InactiveTimerSec:   300,
					},
				},
			},
			runtimeApplyFn: func(context.Context, Settings) error {
				return runtimeApplyErr
			},
			wantErr:        runtimeApplyErr,
			wantLoadCalls:  1,
			wantSaveCalls:  1,
			wantCheckCalls: 1,
			wantApplyCalls: 1,
		},
		{
			name: "success with normalization",
			input: Settings{
				Issuer:             "  https://auth.example.com  ",
				Audience:           "  leshy-controller ",
				JWKSURL:            "  https://auth.example.com/jwks.json ",
				RequiredScope:      " allow:write ",
				GuardedPortsRange:  "1024-2048",
				Iface:              " " + iface + " ",
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
			repo: repositoryStub{
				loadSettings: StoredSettings{
					Settings: Settings{
						Issuer:             "https://auth.example.com",
						Audience:           "leshy-controller",
						JWKSURL:            "https://auth.example.com/jwks.json",
						RequiredScope:      "allow:write",
						GuardedPortsRange:  "1024-2048",
						Iface:              iface,
						HandshakeWindowSec: 600,
						InactiveTimerSec:   300,
					},
				},
			},
			runtimeStatus: RuntimeStatus{
				Attached: true,
				Iface:    iface,
			},
			wantLoadCalls:  1,
			wantSaveCalls:  1,
			wantCheckCalls: 1,
			wantApplyCalls: 1,
			wantNormalized: Settings{
				Issuer:             "https://auth.example.com",
				Audience:           "leshy-controller",
				JWKSURL:            "https://auth.example.com/jwks.json",
				RequiredScope:      "allow:write",
				GuardedPortsRange:  "1024-2048",
				Iface:              iface,
				HandshakeWindowSec: 600,
				InactiveTimerSec:   300,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			repo := tt.repo
			verifier := &verifierStub{validateFn: tt.verifierFn}
			applier := &runtimeApplierStub{
				applyFn: tt.runtimeApplyFn,
				statusFn: func(context.Context) RuntimeStatus {
					return tt.runtimeStatus
				},
			}
			service := New(&repo, verifier, Options{RuntimeApplier: applier})

			stored, err := service.UpdateSettings(context.Background(), tt.input)
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

			if repo.loadCalls != tt.wantLoadCalls {
				t.Fatalf("repository load calls = %d, want %d", repo.loadCalls, tt.wantLoadCalls)
			}
			if repo.saveCalls != tt.wantSaveCalls {
				t.Fatalf("repository save calls = %d, want %d", repo.saveCalls, tt.wantSaveCalls)
			}
			if verifier.validateCalls != tt.wantCheckCalls {
				t.Fatalf("verifier validate calls = %d, want %d", verifier.validateCalls, tt.wantCheckCalls)
			}
			if applier.applyCalls != tt.wantApplyCalls {
				t.Fatalf("runtime apply calls = %d, want %d", applier.applyCalls, tt.wantApplyCalls)
			}
			if tt.wantSaveCalls > 0 && tt.wantNormalized != (Settings{}) && repo.saved != tt.wantNormalized {
				t.Fatalf("saved settings = %+v, want %+v", repo.saved, tt.wantNormalized)
			}
			if tt.wantErr == nil && stored.Runtime != tt.runtimeStatus {
				t.Fatalf("stored runtime status = %+v, want %+v", stored.Runtime, tt.runtimeStatus)
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

func TestServiceRuntimeStatus(t *testing.T) {
	t.Parallel()

	iface := getUpInterface(t)
	expected := RuntimeStatus{
		Attached: true,
		Iface:    iface,
	}

	service := New(&repositoryStub{}, &verifierStub{}, Options{
		RuntimeStatusProvider: &runtimeApplierStub{
			statusFn: func(context.Context) RuntimeStatus {
				return expected
			},
		},
	})

	got := service.RuntimeStatus(context.Background())
	if got != expected {
		t.Fatalf("runtime status = %+v, want %+v", got, expected)
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
