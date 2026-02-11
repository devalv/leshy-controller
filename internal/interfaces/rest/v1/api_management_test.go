package v1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devalv/leshy-controller/internal/application/management"
)

type managementUseCaseStub struct {
	saveCalls               int
	getCalls                int
	authorizeCalls          int
	bootstrapAuthorizeCalls int
	saved                   management.Settings
	runtimeStatus           management.RuntimeStatus
	saveFn                  func(ctx context.Context, settings management.Settings) (management.StoredSettings, error)
	getFn                   func(ctx context.Context) (management.StoredSettings, error)
	authorizeFn             func(ctx context.Context, accessToken string) error
	authorizeSettingsFn     func(ctx context.Context, bootstrapToken string) error
}

func (s *managementUseCaseStub) SaveSettings(
	ctx context.Context,
	settings management.Settings,
) (management.StoredSettings, error) {
	s.saveCalls++
	s.saved = settings
	if s.saveFn != nil {
		return s.saveFn(ctx, settings)
	}

	return management.StoredSettings{
		Settings:  settings,
		UpdatedAt: time.Date(2026, time.January, 10, 12, 0, 0, 0, time.UTC),
		Runtime: management.RuntimeStatus{
			Attached: true,
			Iface:    settings.Iface,
		},
	}, nil
}

func (s *managementUseCaseStub) GetSettings(ctx context.Context) (management.StoredSettings, error) {
	s.getCalls++
	if s.getFn != nil {
		return s.getFn(ctx)
	}

	return management.StoredSettings{
		Settings: management.Settings{
			Issuer:             "https://auth.example.com",
			Audience:           "leshy-controller",
			JWKSURL:            "https://auth.example.com/jwks.json",
			RequiredScope:      "allow:write",
			GuardedPortsRange:  "3389-3391",
			Iface:              "eth0",
			HandshakeWindowSec: 600,
		},
		UpdatedAt: time.Date(2026, time.January, 10, 12, 0, 0, 0, time.UTC),
		Runtime: management.RuntimeStatus{
			Attached: true,
			Iface:    "eth0",
		},
	}, nil
}

func (s *managementUseCaseStub) AuthorizeAllow(ctx context.Context, accessToken string) error {
	s.authorizeCalls++
	if s.authorizeFn != nil {
		return s.authorizeFn(ctx, accessToken)
	}

	return nil
}

func (s *managementUseCaseStub) AuthorizeSettingsBootstrap(ctx context.Context, bootstrapToken string) error {
	s.bootstrapAuthorizeCalls++
	if s.authorizeSettingsFn != nil {
		return s.authorizeSettingsFn(ctx, bootstrapToken)
	}

	return nil
}

func (s *managementUseCaseStub) RuntimeStatus(context.Context) management.RuntimeStatus {
	return s.runtimeStatus
}

func TestManagementSettingsPostEndpoint(t *testing.T) {
	t.Parallel()

	internalErr := errors.New("db failed")

	tests := []struct {
		name               string
		method             string
		body               string
		bootstrapHeader    string
		bootstrapErr       error
		useCaseErr         error
		wantStatus         int
		wantBodyContains   string
		wantSaveCalls      int
		wantBootstrapCalls int
	}{
		{
			name:               "method not allowed",
			method:             http.MethodDelete,
			body:               "",
			wantStatus:         http.StatusMethodNotAllowed,
			wantBodyContains:   "Method not allowed",
			wantSaveCalls:      0,
			wantBootstrapCalls: 0,
		},
		{
			name:               "missing bootstrap header",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600}`,
			bootstrapErr:       management.ErrInvalidBootstrapToken,
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "invalid bootstrap token",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600}`,
			bootstrapHeader:    "bad-token",
			bootstrapErr:       management.ErrInvalidBootstrapToken,
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "bootstrap is locked after pairing",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600}`,
			bootstrapHeader:    "bootstrap",
			bootstrapErr:       management.ErrBootstrapLocked,
			wantStatus:         http.StatusConflict,
			wantBodyContains:   "management settings are locked",
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "bootstrap is not configured",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600}`,
			bootstrapHeader:    "bootstrap",
			bootstrapErr:       management.ErrBootstrapNotConfigured,
			wantStatus:         http.StatusServiceUnavailable,
			wantBodyContains:   "management bootstrap is not configured",
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "invalid json",
			method:             http.MethodPost,
			body:               "{",
			bootstrapHeader:    "bootstrap",
			wantStatus:         http.StatusBadRequest,
			wantBodyContains:   "Invalid JSON",
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "missing issuer",
			method:             http.MethodPost,
			body:               `{"audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600}`,
			bootstrapHeader:    "bootstrap",
			wantStatus:         http.StatusBadRequest,
			wantBodyContains:   "issuer is required",
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "missing handshake window",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0"}`,
			bootstrapHeader:    "bootstrap",
			wantStatus:         http.StatusBadRequest,
			wantBodyContains:   "handshake_window_sec is required",
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "domain validation error",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600}`,
			bootstrapHeader:    "bootstrap",
			useCaseErr:         management.ErrInvalidGuardedPortsRange,
			wantStatus:         http.StatusBadRequest,
			wantBodyContains:   "invalid guarded ports range",
			wantSaveCalls:      1,
			wantBootstrapCalls: 1,
		},
		{
			name:               "internal usecase error",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600}`,
			bootstrapHeader:    "bootstrap",
			useCaseErr:         internalErr,
			wantStatus:         http.StatusInternalServerError,
			wantBodyContains:   "failed to save management settings",
			wantSaveCalls:      1,
			wantBootstrapCalls: 1,
		},
		{
			name:               "success",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600}`,
			bootstrapHeader:    "bootstrap",
			wantStatus:         http.StatusOK,
			wantBodyContains:   `"runtime_attached":true`,
			wantSaveCalls:      1,
			wantBootstrapCalls: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &managementUseCaseStub{
				authorizeSettingsFn: func(context.Context, string) error {
					if tt.bootstrapErr != nil {
						return tt.bootstrapErr
					}

					return nil
				},
				saveFn: func(
					context.Context,
					management.Settings,
				) (management.StoredSettings, error) {
					if tt.useCaseErr != nil {
						return management.StoredSettings{}, tt.useCaseErr
					}

					return management.StoredSettings{
						Settings: management.Settings{
							Issuer:             "https://auth.example.com",
							Audience:           "leshy-controller",
							JWKSURL:            "https://auth.example.com/jwks.json",
							RequiredScope:      "allow:write",
							GuardedPortsRange:  "3389-3391",
							Iface:              "eth0",
							HandshakeWindowSec: 600,
						},
						UpdatedAt: time.Date(2026, time.January, 10, 12, 0, 0, 0, time.UTC),
						Runtime: management.RuntimeStatus{
							Attached: true,
							Iface:    "eth0",
						},
					}, nil
				},
			}

			mux := http.NewServeMux()
			Register(mux, Deps{
				Management: stub,
			})

			request := httptest.NewRequest(tt.method, "/management/settings", strings.NewReader(tt.body))
			if tt.bootstrapHeader != "" {
				request.Header.Set(settingsBootstrapHeader, tt.bootstrapHeader)
			}
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}

			if !strings.Contains(response.Body.String(), tt.wantBodyContains) {
				t.Fatalf("body = %q, expected substring %q", response.Body.String(), tt.wantBodyContains)
			}

			if stub.saveCalls != tt.wantSaveCalls {
				t.Fatalf("save calls = %d, want %d", stub.saveCalls, tt.wantSaveCalls)
			}
			if stub.bootstrapAuthorizeCalls != tt.wantBootstrapCalls {
				t.Fatalf("bootstrap authorize calls = %d, want %d", stub.bootstrapAuthorizeCalls, tt.wantBootstrapCalls)
			}
		})
	}
}

func TestManagementSettingsGetEndpoint(t *testing.T) {
	t.Parallel()

	internalErr := errors.New("db failed")

	tests := []struct {
		name             string
		getErr           error
		wantStatus       int
		wantBodyContains string
	}{
		{
			name:             "not found",
			getErr:           management.ErrSettingsNotFound,
			wantStatus:       http.StatusNotFound,
			wantBodyContains: "management settings not found",
		},
		{
			name:             "internal error",
			getErr:           internalErr,
			wantStatus:       http.StatusInternalServerError,
			wantBodyContains: "failed to get management settings",
		},
		{
			name:             "success",
			wantStatus:       http.StatusOK,
			wantBodyContains: `"runtime_attached":true`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &managementUseCaseStub{
				getFn: func(context.Context) (management.StoredSettings, error) {
					if tt.getErr != nil {
						return management.StoredSettings{}, tt.getErr
					}

					return management.StoredSettings{
						Settings: management.Settings{
							Issuer:             "https://auth.example.com",
							Audience:           "leshy-controller",
							JWKSURL:            "https://auth.example.com/jwks.json",
							RequiredScope:      "allow:write",
							GuardedPortsRange:  "3389-3391",
							Iface:              "eth0",
							HandshakeWindowSec: 600,
						},
						UpdatedAt: time.Date(2026, time.January, 10, 12, 0, 0, 0, time.UTC),
						Runtime: management.RuntimeStatus{
							Attached: true,
							Iface:    "eth0",
						},
					}, nil
				},
			}

			mux := http.NewServeMux()
			Register(mux, Deps{
				Management: stub,
			})

			request := httptest.NewRequest(http.MethodGet, "/management/settings", nil)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}

			if !strings.Contains(response.Body.String(), tt.wantBodyContains) {
				t.Fatalf("body = %q, expected substring %q", response.Body.String(), tt.wantBodyContains)
			}

			if tt.wantStatus == http.StatusOK && strings.Contains(response.Body.String(), `"token":"`) {
				t.Fatalf("body should not expose token: %q", response.Body.String())
			}

			if stub.getCalls != 1 {
				t.Fatalf("get calls = %d, want 1", stub.getCalls)
			}
		})
	}
}
