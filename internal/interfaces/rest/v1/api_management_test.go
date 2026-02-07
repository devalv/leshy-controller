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
	saveCalls int
	getCalls  int
	saved     management.Settings
	saveFn    func(ctx context.Context, settings management.Settings) (management.StoredSettings, error)
	getFn     func(ctx context.Context) (management.StoredSettings, error)
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
	}, nil
}

func (s *managementUseCaseStub) GetSettings(ctx context.Context) (management.StoredSettings, error) {
	s.getCalls++
	if s.getFn != nil {
		return s.getFn(ctx)
	}

	return management.StoredSettings{
		Settings: management.Settings{
			Token:             "secret",
			GuardedPortsRange: "3389-3391",
			Iface:             "eth0",
		},
		UpdatedAt: time.Date(2026, time.January, 10, 12, 0, 0, 0, time.UTC),
	}, nil
}

func TestManagementSettingsPostEndpoint(t *testing.T) {
	t.Parallel()

	internalErr := errors.New("db failed")

	tests := []struct {
		name             string
		method           string
		body             string
		useCaseErr       error
		wantStatus       int
		wantBodyContains string
		wantSaveCalls    int
	}{
		{
			name:             "method not allowed",
			method:           http.MethodDelete,
			body:             "",
			wantStatus:       http.StatusMethodNotAllowed,
			wantBodyContains: "Method not allowed",
			wantSaveCalls:    0,
		},
		{
			name:             "invalid json",
			method:           http.MethodPost,
			body:             "{",
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: "Invalid JSON",
			wantSaveCalls:    0,
		},
		{
			name:             "missing token",
			method:           http.MethodPost,
			body:             `{"guarded_ports_range":"3389-3391","iface":"eth0"}`,
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: "token is required",
			wantSaveCalls:    0,
		},
		{
			name:             "domain validation error",
			method:           http.MethodPost,
			body:             `{"token":"abc","guarded_ports_range":"3389-3391","iface":"eth0"}`,
			useCaseErr:       management.ErrInvalidGuardedPortsRange,
			wantStatus:       http.StatusBadRequest,
			wantBodyContains: "invalid guarded ports range",
			wantSaveCalls:    1,
		},
		{
			name:             "internal usecase error",
			method:           http.MethodPost,
			body:             `{"token":"abc","guarded_ports_range":"3389-3391","iface":"eth0"}`,
			useCaseErr:       internalErr,
			wantStatus:       http.StatusInternalServerError,
			wantBodyContains: "failed to save management settings",
			wantSaveCalls:    1,
		},
		{
			name:             "success",
			method:           http.MethodPost,
			body:             `{"token":"abc","guarded_ports_range":"3389-3391","iface":"eth0"}`,
			wantStatus:       http.StatusOK,
			wantBodyContains: `"message":"Management settings saved"`,
			wantSaveCalls:    1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			stub := &managementUseCaseStub{
				saveFn: func(
					context.Context,
					management.Settings,
				) (management.StoredSettings, error) {
					if tt.useCaseErr != nil {
						return management.StoredSettings{}, tt.useCaseErr
					}

					return management.StoredSettings{
						Settings: management.Settings{
							Token:             "abc",
							GuardedPortsRange: "3389-3391",
							Iface:             "eth0",
						},
						UpdatedAt: time.Date(2026, time.January, 10, 12, 0, 0, 0, time.UTC),
					}, nil
				},
			}

			mux := http.NewServeMux()
			Register(mux, Deps{
				Management: stub,
			})

			request := httptest.NewRequest(tt.method, "/management/settings", strings.NewReader(tt.body))
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
			wantBodyContains: `"token_configured":true`,
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
							Token:             "secret",
							GuardedPortsRange: "3389-3391",
							Iface:             "eth0",
						},
						UpdatedAt: time.Date(2026, time.January, 10, 12, 0, 0, 0, time.UTC),
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
