package v1

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/devalv/leshy-controller/internal/application/filter"
	"github.com/devalv/leshy-controller/internal/application/management"
)

type filterUseCaseStub struct {
	allowCalls int
	statsCalls int
	blockCalls int
	allowFn    func(ctx context.Context, ip net.IP, port uint16) (time.Time, error)
	statsFn    func(ctx context.Context) (filter.Stats, error)
	blockFn    func(ctx context.Context) (filter.FlushResult, error)
}

func (s *filterUseCaseStub) Allow(ctx context.Context, ip net.IP, port uint16) (time.Time, error) {
	s.allowCalls++
	if s.allowFn == nil {
		return time.Date(2026, time.February, 7, 13, 0, 0, 0, time.UTC), nil
	}

	return s.allowFn(ctx, ip, port)
}

func (s *filterUseCaseStub) Stats(ctx context.Context) (filter.Stats, error) {
	s.statsCalls++
	if s.statsFn == nil {
		return filter.Stats{}, nil
	}

	return s.statsFn(ctx)
}

func (s *filterUseCaseStub) BlockAll(ctx context.Context) (filter.FlushResult, error) {
	s.blockCalls++
	if s.blockFn == nil {
		return filter.FlushResult{}, nil
	}

	return s.blockFn(ctx)
}

func TestAllowEndpointAuthorization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		authHeader       string
		authorizeErr     error
		wantStatus       int
		wantBodyContains string
		wantAllowCalls   int
	}{
		{
			name:             "missing auth header",
			authHeader:       "",
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "Unauthorized",
			wantAllowCalls:   0,
		},
		{
			name:             "invalid auth scheme",
			authHeader:       "Basic abc",
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "Unauthorized",
			wantAllowCalls:   0,
		},
		{
			name:             "invalid access token",
			authHeader:       "Bearer bad-token",
			authorizeErr:     management.ErrInvalidAccessToken,
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "Unauthorized",
			wantAllowCalls:   0,
		},
		{
			name:             "settings are not configured",
			authHeader:       "Bearer token",
			authorizeErr:     management.ErrSettingsNotFound,
			wantStatus:       http.StatusServiceUnavailable,
			wantBodyContains: "Authorization is unavailable",
			wantAllowCalls:   0,
		},
		{
			name:             "authorization backend unavailable",
			authHeader:       "Bearer token",
			authorizeErr:     management.ErrAuthorizationUnavailable,
			wantStatus:       http.StatusServiceUnavailable,
			wantBodyContains: "Authorization is unavailable",
			wantAllowCalls:   0,
		},
		{
			name:             "authorized request",
			authHeader:       "Bearer token",
			wantStatus:       http.StatusOK,
			wantBodyContains: `"message":"Access granted"`,
			wantAllowCalls:   1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filterStub := &filterUseCaseStub{}
			managementStub := &managementUseCaseStub{
				authorizeFn: func(context.Context, string) error {
					if tt.authorizeErr != nil {
						return tt.authorizeErr
					}

					return nil
				},
			}

			mux := http.NewServeMux()
			Register(mux, Deps{
				Filter:     filterStub,
				Management: managementStub,
			})

			request := httptest.NewRequest(http.MethodPost, "/allow", strings.NewReader(`{"ip":"127.0.0.1","port":3389}`))
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
			if filterStub.allowCalls != tt.wantAllowCalls {
				t.Fatalf("allow calls = %d, want %d", filterStub.allowCalls, tt.wantAllowCalls)
			}
		})
	}
}

func TestAllowEndpointAuthorizationFailureIsInternalError(t *testing.T) {
	t.Parallel()

	filterStub := &filterUseCaseStub{}
	managementStub := &managementUseCaseStub{
		authorizeFn: func(context.Context, string) error {
			return errors.New("unexpected verifier error")
		},
	}

	mux := http.NewServeMux()
	Register(mux, Deps{
		Filter:     filterStub,
		Management: managementStub,
	})

	request := httptest.NewRequest(http.MethodPost, "/allow", strings.NewReader(`{"ip":"127.0.0.1","port":3389}`))
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	if !strings.Contains(response.Body.String(), "allow authorization failed") {
		t.Fatalf("body = %q, expected allow authorization failed", response.Body.String())
	}
}

func TestAllowEndpointReturnsServiceUnavailableWhenFilterNotConfigured(t *testing.T) {
	t.Parallel()

	filterStub := &filterUseCaseStub{
		allowFn: func(context.Context, net.IP, uint16) (time.Time, error) {
			return time.Time{}, filter.ErrNotConfigured
		},
	}
	managementStub := &managementUseCaseStub{
		authorizeFn: func(context.Context, string) error {
			return nil
		},
	}

	mux := http.NewServeMux()
	Register(mux, Deps{
		Filter:     filterStub,
		Management: managementStub,
	})

	request := httptest.NewRequest(http.MethodPost, "/allow", strings.NewReader(`{"ip":"127.0.0.1","port":3389}`))
	request.Header.Set("Authorization", "Bearer token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(response.Body.String(), "filter is not configured") {
		t.Fatalf("body = %q, expected filter is not configured", response.Body.String())
	}
}

func TestAllowEndpointMethodNotAllowedSkipsAuthorization(t *testing.T) {
	t.Parallel()

	filterStub := &filterUseCaseStub{}
	managementStub := &managementUseCaseStub{
		authorizeFn: func(context.Context, string) error {
			return nil
		},
	}

	mux := http.NewServeMux()
	Register(mux, Deps{
		Filter:     filterStub,
		Management: managementStub,
	})

	request := httptest.NewRequest(http.MethodGet, "/allow", nil)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	if managementStub.authorizeCalls != 0 {
		t.Fatalf("authorize calls = %d, want 0", managementStub.authorizeCalls)
	}
}

func TestStatsEndpointAuthorization(t *testing.T) {
	t.Parallel()

	internalErr := errors.New("unexpected verifier error")

	tests := []struct {
		name               string
		method             string
		authHeader         string
		authorizeErr       error
		statsErr           error
		wantStatus         int
		wantBodyContains   string
		wantAuthorizeCalls int
		wantStatsCalls     int
	}{
		{
			name:               "method not allowed skips authorization",
			method:             http.MethodPost,
			wantStatus:         http.StatusMethodNotAllowed,
			wantBodyContains:   "Method not allowed",
			wantAuthorizeCalls: 0,
			wantStatsCalls:     0,
		},
		{
			name:               "missing auth header",
			method:             http.MethodGet,
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 0,
			wantStatsCalls:     0,
		},
		{
			name:               "invalid auth scheme",
			method:             http.MethodGet,
			authHeader:         "Basic abc",
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 0,
			wantStatsCalls:     0,
		},
		{
			name:               "invalid access token",
			method:             http.MethodGet,
			authHeader:         "Bearer bad-token",
			authorizeErr:       management.ErrInvalidAccessToken,
			wantStatus:         http.StatusUnauthorized,
			wantBodyContains:   "Unauthorized",
			wantAuthorizeCalls: 1,
			wantStatsCalls:     0,
		},
		{
			name:               "settings are not configured",
			method:             http.MethodGet,
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrSettingsNotFound,
			wantStatus:         http.StatusServiceUnavailable,
			wantBodyContains:   "Authorization is unavailable",
			wantAuthorizeCalls: 1,
			wantStatsCalls:     0,
		},
		{
			name:               "authorization backend unavailable",
			method:             http.MethodGet,
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrAuthorizationUnavailable,
			wantStatus:         http.StatusServiceUnavailable,
			wantBodyContains:   "Authorization is unavailable",
			wantAuthorizeCalls: 1,
			wantStatsCalls:     0,
		},
		{
			name:               "authorization failure is internal error",
			method:             http.MethodGet,
			authHeader:         "Bearer token",
			authorizeErr:       internalErr,
			wantStatus:         http.StatusInternalServerError,
			wantBodyContains:   "stats authorization failed",
			wantAuthorizeCalls: 1,
			wantStatsCalls:     0,
		},
		{
			name:               "filter not configured",
			method:             http.MethodGet,
			authHeader:         "Bearer token",
			statsErr:           filter.ErrNotConfigured,
			wantStatus:         http.StatusServiceUnavailable,
			wantBodyContains:   "filter is not configured",
			wantAuthorizeCalls: 1,
			wantStatsCalls:     1,
		},
		{
			name:               "authorized request",
			method:             http.MethodGet,
			authHeader:         "Bearer token",
			wantStatus:         http.StatusOK,
			wantBodyContains:   `"allowed":7`,
			wantAuthorizeCalls: 1,
			wantStatsCalls:     1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filterStub := &filterUseCaseStub{
				statsFn: func(context.Context) (filter.Stats, error) {
					if tt.statsErr != nil {
						return filter.Stats{}, tt.statsErr
					}

					return filter.Stats{
						Counters: filter.Counters{
							Allowed: 7,
							Dropped: 2,
						},
						AllowRatePercent: 77.7,
						DropRatePercent:  22.3,
					}, nil
				},
			}
			managementStub := &managementUseCaseStub{
				authorizeFn: func(context.Context, string) error {
					if tt.authorizeErr != nil {
						return tt.authorizeErr
					}

					return nil
				},
			}

			mux := http.NewServeMux()
			Register(mux, Deps{
				Filter:     filterStub,
				Management: managementStub,
			})

			request := httptest.NewRequest(tt.method, "/stats", nil)
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
			if filterStub.statsCalls != tt.wantStatsCalls {
				t.Fatalf("stats calls = %d, want %d", filterStub.statsCalls, tt.wantStatsCalls)
			}
		})
	}
}
