package v1

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devalv/leshy-controller/internal/application/filter"
	"github.com/devalv/leshy-controller/internal/application/management"
)

type managementUseCaseStub struct {
	saveCalls               int
	updateCalls             int
	getCalls                int
	authorizeCalls          int
	bootstrapAuthorizeCalls int
	saved                   management.Settings
	updated                 management.Settings
	runtimeStatus           management.RuntimeStatus
	saveFn                  func(ctx context.Context, settings management.Settings) (management.StoredSettings, error)
	updateFn                func(ctx context.Context, settings management.Settings) (management.StoredSettings, error)
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

func (s *managementUseCaseStub) UpdateSettings(
	ctx context.Context,
	settings management.Settings,
) (management.StoredSettings, error) {
	s.updateCalls++
	s.updated = settings
	if s.updateFn != nil {
		return s.updateFn(ctx, settings)
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
			InactiveTimerSec:   300,
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
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
			bootstrapErr:       management.ErrInvalidBootstrapToken,
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "invalid bootstrap token",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
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
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
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
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
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
			body:               `{"audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
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
			name:               "missing inactive timer",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600}`,
			bootstrapHeader:    "bootstrap",
			wantStatus:         http.StatusBadRequest,
			wantBodyContains:   "inactive_timer_sec is required",
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "domain validation error",
			method:             http.MethodPost,
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
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
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
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
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
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
							InactiveTimerSec:   300,
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

func TestManagementSettingsPatchEndpoint(t *testing.T) {
	t.Parallel()

	internalErr := errors.New("db failed")

	tests := []struct {
		name               string
		body               string
		authHeader         string
		authorizeErr       error
		useCaseErr         error
		wantStatus         int
		wantBodyContains   string
		wantAuthorizeCalls int
		wantUpdateCalls    int
	}{
		{
			name:               "missing authorization header",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 0,
			wantUpdateCalls:    0,
		},
		{
			name:               "invalid authorization scheme",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
			authHeader:         "Basic abc",
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 0,
			wantUpdateCalls:    0,
		},
		{
			name:               "invalid access token",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
			authHeader:         "Bearer bad-token",
			authorizeErr:       management.ErrInvalidAccessToken,
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 1,
			wantUpdateCalls:    0,
		},
		{
			name:               "settings are not configured",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrSettingsNotFound,
			wantStatus:         http.StatusConflict,
			wantBodyContains:   "management settings are not configured",
			wantAuthorizeCalls: 1,
			wantUpdateCalls:    0,
		},
		{
			name:               "authorization backend unavailable",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrAuthorizationUnavailable,
			wantStatus:         http.StatusServiceUnavailable,
			wantBodyContains:   "Authorization is unavailable",
			wantAuthorizeCalls: 1,
			wantUpdateCalls:    0,
		},
		{
			name:               "invalid json",
			body:               "{",
			authHeader:         "Bearer token",
			wantStatus:         http.StatusBadRequest,
			wantBodyContains:   "Invalid JSON",
			wantAuthorizeCalls: 1,
			wantUpdateCalls:    0,
		},
		{
			name:               "missing required field",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0"}`,
			authHeader:         "Bearer token",
			wantStatus:         http.StatusBadRequest,
			wantBodyContains:   "handshake_window_sec is required",
			wantAuthorizeCalls: 1,
			wantUpdateCalls:    0,
		},
		{
			name:               "missing inactive timer",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600}`,
			authHeader:         "Bearer token",
			wantStatus:         http.StatusBadRequest,
			wantBodyContains:   "inactive_timer_sec is required",
			wantAuthorizeCalls: 1,
			wantUpdateCalls:    0,
		},
		{
			name:               "settings removed between auth and update",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
			authHeader:         "Bearer token",
			useCaseErr:         management.ErrSettingsNotFound,
			wantStatus:         http.StatusConflict,
			wantBodyContains:   "management settings are not configured",
			wantAuthorizeCalls: 1,
			wantUpdateCalls:    1,
		},
		{
			name:               "domain validation error",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
			authHeader:         "Bearer token",
			useCaseErr:         management.ErrInvalidGuardedPortsRange,
			wantStatus:         http.StatusBadRequest,
			wantBodyContains:   "invalid guarded ports range",
			wantAuthorizeCalls: 1,
			wantUpdateCalls:    1,
		},
		{
			name:               "internal usecase error",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
			authHeader:         "Bearer token",
			useCaseErr:         internalErr,
			wantStatus:         http.StatusInternalServerError,
			wantBodyContains:   "failed to update management settings",
			wantAuthorizeCalls: 1,
			wantUpdateCalls:    1,
		},
		{
			name:               "success",
			body:               `{"issuer":"https://auth.example.com","audience":"leshy-controller","jwks_url":"https://auth.example.com/jwks.json","required_scope":"allow:write","guarded_ports_range":"3389-3391","iface":"eth0","handshake_window_sec":600,"inactive_timer_sec":300}`,
			authHeader:         "Bearer token",
			wantStatus:         http.StatusOK,
			wantBodyContains:   `"message":"Management settings updated"`,
			wantAuthorizeCalls: 1,
			wantUpdateCalls:    1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &managementUseCaseStub{
				authorizeFn: func(context.Context, string) error {
					if tt.authorizeErr != nil {
						return tt.authorizeErr
					}

					return nil
				},
				updateFn: func(
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
							InactiveTimerSec:   300,
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

			request := httptest.NewRequest(http.MethodPatch, "/management/settings", strings.NewReader(tt.body))
			if tt.authHeader != "" {
				request.Header.Set("Authorization", tt.authHeader)
			}
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			if !strings.Contains(response.Body.String(), tt.wantBodyContains) {
				t.Fatalf("body = %q, expected substring %q", response.Body.String(), tt.wantBodyContains)
			}
			if stub.authorizeCalls != tt.wantAuthorizeCalls {
				t.Fatalf("authorize calls = %d, want %d", stub.authorizeCalls, tt.wantAuthorizeCalls)
			}
			if stub.updateCalls != tt.wantUpdateCalls {
				t.Fatalf("update calls = %d, want %d", stub.updateCalls, tt.wantUpdateCalls)
			}
			if stub.bootstrapAuthorizeCalls != 0 {
				t.Fatalf("bootstrap authorize calls = %d, want 0", stub.bootstrapAuthorizeCalls)
			}
		})
	}
}

func TestManagementBlockEndpoint(t *testing.T) {
	t.Parallel()

	internalErr := errors.New("flush failed")

	tests := []struct {
		name               string
		method             string
		authHeader         string
		authorizeErr       error
		blockErr           error
		blockResult        filter.FlushResult
		wantStatus         int
		wantBodyContains   string
		wantAuthorizeCalls int
		wantBlockCalls     int
	}{
		{
			name:               "method not allowed",
			method:             http.MethodGet,
			wantStatus:         http.StatusMethodNotAllowed,
			wantBodyContains:   "Method not allowed",
			wantAuthorizeCalls: 0,
			wantBlockCalls:     0,
		},
		{
			name:               "missing authorization header",
			method:             http.MethodPost,
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 0,
			wantBlockCalls:     0,
		},
		{
			name:               "invalid access token",
			method:             http.MethodPost,
			authHeader:         "Bearer bad-token",
			authorizeErr:       management.ErrInvalidAccessToken,
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 1,
			wantBlockCalls:     0,
		},
		{
			name:               "settings are not configured",
			method:             http.MethodPost,
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrSettingsNotFound,
			wantStatus:         http.StatusConflict,
			wantBodyContains:   "management settings are not configured",
			wantAuthorizeCalls: 1,
			wantBlockCalls:     0,
		},
		{
			name:               "authorization unavailable",
			method:             http.MethodPost,
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrAuthorizationUnavailable,
			wantStatus:         http.StatusServiceUnavailable,
			wantBodyContains:   "Authorization is unavailable",
			wantAuthorizeCalls: 1,
			wantBlockCalls:     0,
		},
		{
			name:               "filter is not configured",
			method:             http.MethodPost,
			authHeader:         "Bearer token",
			blockErr:           filter.ErrNotConfigured,
			wantStatus:         http.StatusServiceUnavailable,
			wantBodyContains:   "filter is not configured",
			wantAuthorizeCalls: 1,
			wantBlockCalls:     1,
		},
		{
			name:               "internal filter error",
			method:             http.MethodPost,
			authHeader:         "Bearer token",
			blockErr:           internalErr,
			wantStatus:         http.StatusInternalServerError,
			wantBodyContains:   "failed to block all connections",
			wantAuthorizeCalls: 1,
			wantBlockCalls:     1,
		},
		{
			name:       "success",
			method:     http.MethodPost,
			authHeader: "Bearer token",
			blockResult: filter.FlushResult{
				PendingEntriesRemoved: 3,
				ActiveFlowsRemoved:    2,
			},
			wantStatus:         http.StatusOK,
			wantBodyContains:   `"active_flows_removed":2`,
			wantAuthorizeCalls: 1,
			wantBlockCalls:     1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			managementStub := &managementUseCaseStub{
				authorizeFn: func(context.Context, string) error {
					if tt.authorizeErr != nil {
						return tt.authorizeErr
					}

					return nil
				},
				runtimeStatus: management.RuntimeStatus{
					Attached: true,
					Iface:    "eth0",
				},
			}
			filterStub := &filterUseCaseStub{
				blockFn: func(context.Context) (filter.FlushResult, error) {
					if tt.blockErr != nil {
						return filter.FlushResult{}, tt.blockErr
					}

					return tt.blockResult, nil
				},
			}

			mux := http.NewServeMux()
			Register(mux, Deps{
				Filter:     filterStub,
				Management: managementStub,
			})

			request := httptest.NewRequest(tt.method, "/management/block", nil)
			if tt.authHeader != "" {
				request.Header.Set("Authorization", tt.authHeader)
			}
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)

			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			if !strings.Contains(response.Body.String(), tt.wantBodyContains) {
				t.Fatalf("body = %q, expected substring %q", response.Body.String(), tt.wantBodyContains)
			}
			if managementStub.authorizeCalls != tt.wantAuthorizeCalls {
				t.Fatalf("authorize calls = %d, want %d", managementStub.authorizeCalls, tt.wantAuthorizeCalls)
			}
			if filterStub.blockCalls != tt.wantBlockCalls {
				t.Fatalf("block calls = %d, want %d", filterStub.blockCalls, tt.wantBlockCalls)
			}
		})
	}
}

func TestSourceIPFromRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remoteAddr string
		want       string
	}{
		{
			name:       "ipv4 with port",
			remoteAddr: "203.0.113.10:55213",
			want:       "203.0.113.10",
		},
		{
			name:       "ipv6 with port",
			remoteAddr: "[2001:db8::1]:443",
			want:       "2001:db8::1",
		},
		{
			name:       "plain ipv4 without port",
			remoteAddr: "198.51.100.7",
			want:       "198.51.100.7",
		},
		{
			name:       "invalid remote addr",
			remoteAddr: "bad-remote-addr",
			want:       "bad-remote-addr",
		},
		{
			name:       "empty remote addr",
			remoteAddr: "",
			want:       "unknown",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequest(http.MethodPost, "/management/settings", nil)
			request.RemoteAddr = tt.remoteAddr

			got := sourceIPFromRequest(request)
			if got != tt.want {
				t.Fatalf("sourceIPFromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestManagementSettingsGetEndpoint(t *testing.T) {
	t.Parallel()

	internalErr := errors.New("db failed")

	tests := []struct {
		name               string
		authHeader         string
		authorizeErr       error
		getErr             error
		wantStatus         int
		wantBodyContains   string
		wantAuthorizeCalls int
		wantGetCalls       int
	}{
		{
			name:               "missing authorization header",
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 0,
			wantGetCalls:       0,
		},
		{
			name:               "invalid authorization scheme",
			authHeader:         "Basic abc",
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 0,
			wantGetCalls:       0,
		},
		{
			name:               "invalid access token",
			authHeader:         "Bearer bad-token",
			authorizeErr:       management.ErrInvalidAccessToken,
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 1,
			wantGetCalls:       0,
		},
		{
			name:               "settings are not configured",
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrSettingsNotFound,
			wantStatus:         http.StatusConflict,
			wantBodyContains:   "management settings are not configured",
			wantAuthorizeCalls: 1,
			wantGetCalls:       0,
		},
		{
			name:               "authorization unavailable",
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrAuthorizationUnavailable,
			wantStatus:         http.StatusServiceUnavailable,
			wantBodyContains:   "Authorization is unavailable",
			wantAuthorizeCalls: 1,
			wantGetCalls:       0,
		},
		{
			name:               "authorization failure",
			authHeader:         "Bearer token",
			authorizeErr:       errors.New("verifier failed"),
			wantStatus:         http.StatusInternalServerError,
			wantBodyContains:   "management settings authorization failed",
			wantAuthorizeCalls: 1,
			wantGetCalls:       0,
		},
		{
			name:               "not found",
			authHeader:         "Bearer token",
			getErr:             management.ErrSettingsNotFound,
			wantStatus:         http.StatusNotFound,
			wantBodyContains:   "management settings not found",
			wantAuthorizeCalls: 1,
			wantGetCalls:       1,
		},
		{
			name:               "internal error",
			authHeader:         "Bearer token",
			getErr:             internalErr,
			wantStatus:         http.StatusInternalServerError,
			wantBodyContains:   "failed to get management settings",
			wantAuthorizeCalls: 1,
			wantGetCalls:       1,
		},
		{
			name:               "success",
			authHeader:         "Bearer token",
			wantStatus:         http.StatusOK,
			wantBodyContains:   `"runtime_attached":true`,
			wantAuthorizeCalls: 1,
			wantGetCalls:       1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &managementUseCaseStub{
				authorizeFn: func(context.Context, string) error {
					if tt.authorizeErr != nil {
						return tt.authorizeErr
					}

					return nil
				},
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
							InactiveTimerSec:   300,
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
			if tt.authHeader != "" {
				request.Header.Set("Authorization", tt.authHeader)
			}
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

			if stub.authorizeCalls != tt.wantAuthorizeCalls {
				t.Fatalf("authorize calls = %d, want %d", stub.authorizeCalls, tt.wantAuthorizeCalls)
			}

			if stub.getCalls != tt.wantGetCalls {
				t.Fatalf("get calls = %d, want %d", stub.getCalls, tt.wantGetCalls)
			}
		})
	}
}
