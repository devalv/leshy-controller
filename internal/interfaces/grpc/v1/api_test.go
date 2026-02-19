package v1

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/devalv/leshy-controller/internal/application/filter"
	"github.com/devalv/leshy-controller/internal/application/management"
	grpcv1 "github.com/devalv/leshy-controller/internal/contracts/grpc/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
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
		return time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC), nil
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

type managementUseCaseStub struct {
	saveCalls            int
	updateCalls          int
	getCalls             int
	authorizeCalls       int
	bootstrapCalls       int
	runtimeStatus        management.RuntimeStatus
	saveFn               func(ctx context.Context, settings management.Settings) (management.StoredSettings, error)
	updateFn             func(ctx context.Context, settings management.Settings) (management.StoredSettings, error)
	getFn                func(ctx context.Context) (management.StoredSettings, error)
	authorizeAllowFn     func(ctx context.Context, accessToken string) error
	authorizeBootstrapFn func(ctx context.Context, bootstrapToken string) error
}

func (s *managementUseCaseStub) SaveSettings(
	ctx context.Context,
	settings management.Settings,
) (management.StoredSettings, error) {
	s.saveCalls++
	if s.saveFn != nil {
		return s.saveFn(ctx, settings)
	}

	return management.StoredSettings{
		Settings:  settings,
		UpdatedAt: time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC),
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
	if s.updateFn != nil {
		return s.updateFn(ctx, settings)
	}

	return management.StoredSettings{
		Settings:  settings,
		UpdatedAt: time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC),
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
		UpdatedAt: time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC),
		Runtime: management.RuntimeStatus{
			Attached: true,
			Iface:    "eth0",
		},
	}, nil
}

func (s *managementUseCaseStub) RuntimeStatus(context.Context) management.RuntimeStatus {
	return s.runtimeStatus
}

func (s *managementUseCaseStub) AuthorizeAllow(ctx context.Context, accessToken string) error {
	s.authorizeCalls++
	if s.authorizeAllowFn != nil {
		return s.authorizeAllowFn(ctx, accessToken)
	}

	return nil
}

func (s *managementUseCaseStub) AuthorizeSettingsBootstrap(ctx context.Context, bootstrapToken string) error {
	s.bootstrapCalls++
	if s.authorizeBootstrapFn != nil {
		return s.authorizeBootstrapFn(ctx, bootstrapToken)
	}

	return nil
}

func TestHealth(t *testing.T) {
	t.Parallel()

	api := New(Deps{
		Management: &managementUseCaseStub{
			runtimeStatus: management.RuntimeStatus{
				Attached: true,
				Iface:    "ens18",
			},
		},
	})

	resp, err := api.Health(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.GetStatus() != "ok" {
		t.Fatalf("status = %q, want %q", resp.GetStatus(), "ok")
	}
	if !resp.GetRuntimeAttached() {
		t.Fatalf("runtime_attached = false, want true")
	}
}

func TestAllow(t *testing.T) {
	t.Parallel()

	expiresAt := time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name               string
		authHeader         string
		authorizeErr       error
		requestIP          string
		requestPort        uint32
		allowErr           error
		wantCode           codes.Code
		wantAllowCalls     int
		wantAuthorizeCalls int
	}{
		{
			name:               "missing authorization",
			requestPort:        3389,
			wantCode:           codes.Unauthenticated,
			wantAllowCalls:     0,
			wantAuthorizeCalls: 0,
		},
		{
			name:               "invalid access token",
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrInvalidAccessToken,
			requestPort:        3389,
			wantCode:           codes.Unauthenticated,
			wantAllowCalls:     0,
			wantAuthorizeCalls: 1,
		},
		{
			name:               "settings are not configured",
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrSettingsNotFound,
			requestPort:        3389,
			wantCode:           codes.Unavailable,
			wantAllowCalls:     0,
			wantAuthorizeCalls: 1,
		},
		{
			name:               "authorization unavailable",
			authHeader:         "Bearer token",
			authorizeErr:       management.ErrAuthorizationUnavailable,
			requestPort:        3389,
			wantCode:           codes.Unavailable,
			wantAllowCalls:     0,
			wantAuthorizeCalls: 1,
		},
		{
			name:               "invalid ip",
			authHeader:         "Bearer token",
			requestIP:          "invalid-ip",
			requestPort:        3389,
			wantCode:           codes.InvalidArgument,
			wantAllowCalls:     0,
			wantAuthorizeCalls: 1,
		},
		{
			name:               "invalid port value",
			authHeader:         "Bearer token",
			requestPort:        65536,
			wantCode:           codes.InvalidArgument,
			wantAllowCalls:     0,
			wantAuthorizeCalls: 1,
		},
		{
			name:               "filter not configured",
			authHeader:         "Bearer token",
			requestPort:        3389,
			allowErr:           filter.ErrNotConfigured,
			wantCode:           codes.Unavailable,
			wantAllowCalls:     1,
			wantAuthorizeCalls: 1,
		},
		{
			name:               "success with source ip fallback",
			authHeader:         "Bearer token",
			requestPort:        3389,
			wantCode:           codes.OK,
			wantAllowCalls:     1,
			wantAuthorizeCalls: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			filterStub := &filterUseCaseStub{
				allowFn: func(context.Context, net.IP, uint16) (time.Time, error) {
					if tt.allowErr != nil {
						return time.Time{}, tt.allowErr
					}

					return expiresAt, nil
				},
			}
			managementStub := &managementUseCaseStub{
				authorizeAllowFn: func(context.Context, string) error {
					return tt.authorizeErr
				},
			}
			api := New(Deps{
				Filter:     filterStub,
				Management: managementStub,
			})

			ctx := incomingContext(tt.authHeader, "", "203.0.113.10")
			resp, err := api.Allow(ctx, &grpcv1.AllowRequest{
				Ip:   tt.requestIP,
				Port: tt.requestPort,
			})
			gotCode := status.Code(err)
			if gotCode != tt.wantCode {
				t.Fatalf("code = %v, want %v (err=%v)", gotCode, tt.wantCode, err)
			}

			if tt.wantCode == codes.OK {
				if resp == nil {
					t.Fatal("response is nil")
				}
				if resp.GetExpiresAt().AsTime().UTC() != expiresAt {
					t.Fatalf("expires_at = %v, want %v", resp.GetExpiresAt().AsTime().UTC(), expiresAt)
				}
				if resp.GetIp() != "203.0.113.10" {
					t.Fatalf("ip = %q, want %q", resp.GetIp(), "203.0.113.10")
				}
			}

			if filterStub.allowCalls != tt.wantAllowCalls {
				t.Fatalf("allow calls = %d, want %d", filterStub.allowCalls, tt.wantAllowCalls)
			}
			if managementStub.authorizeCalls != tt.wantAuthorizeCalls {
				t.Fatalf("authorize calls = %d, want %d", managementStub.authorizeCalls, tt.wantAuthorizeCalls)
			}
		})
	}
}

func TestCreateSettings(t *testing.T) {
	t.Parallel()

	validRequest := &grpcv1.UpsertManagementSettingsRequest{
		Issuer:             "https://auth.example.com",
		Audience:           "leshy-controller",
		JwksUrl:            "https://auth.example.com/jwks.json",
		RequiredScope:      "allow:write",
		GuardedPortsRange:  "3389-3391",
		Iface:              "eth0",
		HandshakeWindowSec: 600,
		InactiveTimerSec:   300,
	}

	tests := []struct {
		name               string
		bootstrapHeader    string
		bootstrapErr       error
		request            *grpcv1.UpsertManagementSettingsRequest
		saveErr            error
		wantCode           codes.Code
		wantSaveCalls      int
		wantBootstrapCalls int
	}{
		{
			name:               "invalid bootstrap token",
			bootstrapErr:       management.ErrInvalidBootstrapToken,
			request:            validRequest,
			wantCode:           codes.Unauthenticated,
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "bootstrap locked",
			bootstrapErr:       management.ErrBootstrapLocked,
			request:            validRequest,
			wantCode:           codes.FailedPrecondition,
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "bootstrap not configured",
			bootstrapErr:       management.ErrBootstrapNotConfigured,
			request:            validRequest,
			wantCode:           codes.Unavailable,
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "invalid payload",
			request:            &grpcv1.UpsertManagementSettingsRequest{},
			wantCode:           codes.InvalidArgument,
			wantSaveCalls:      0,
			wantBootstrapCalls: 1,
		},
		{
			name:               "use case validation error",
			request:            validRequest,
			saveErr:            management.ErrInvalidGuardedPortsRange,
			wantCode:           codes.InvalidArgument,
			wantSaveCalls:      1,
			wantBootstrapCalls: 1,
		},
		{
			name:               "success",
			request:            validRequest,
			wantCode:           codes.OK,
			wantSaveCalls:      1,
			wantBootstrapCalls: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			managementStub := &managementUseCaseStub{
				authorizeBootstrapFn: func(context.Context, string) error {
					return tt.bootstrapErr
				},
				saveFn: func(context.Context, management.Settings) (management.StoredSettings, error) {
					if tt.saveErr != nil {
						return management.StoredSettings{}, tt.saveErr
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
						UpdatedAt: time.Date(2026, time.February, 20, 10, 0, 0, 0, time.UTC),
						Runtime: management.RuntimeStatus{
							Attached: true,
							Iface:    "eth0",
						},
					}, nil
				},
			}

			api := New(Deps{
				Management: managementStub,
			})

			ctx := incomingContext("", tt.bootstrapHeader, "203.0.113.11")
			resp, err := api.CreateSettings(ctx, tt.request)
			gotCode := status.Code(err)
			if gotCode != tt.wantCode {
				t.Fatalf("code = %v, want %v (err=%v)", gotCode, tt.wantCode, err)
			}
			if tt.wantCode == codes.OK {
				if resp == nil {
					t.Fatal("response is nil")
				}
				if resp.GetMessage() != "Management settings saved" {
					t.Fatalf("message = %q, want %q", resp.GetMessage(), "Management settings saved")
				}
			}

			if managementStub.saveCalls != tt.wantSaveCalls {
				t.Fatalf("save calls = %d, want %d", managementStub.saveCalls, tt.wantSaveCalls)
			}
			if managementStub.bootstrapCalls != tt.wantBootstrapCalls {
				t.Fatalf("bootstrap calls = %d, want %d", managementStub.bootstrapCalls, tt.wantBootstrapCalls)
			}
		})
	}
}

func TestUpdateGetAndBlock(t *testing.T) {
	t.Parallel()

	t.Run("update settings unauthorized", func(t *testing.T) {
		t.Parallel()

		api := New(Deps{
			Management: &managementUseCaseStub{},
		})

		_, err := api.UpdateSettings(incomingContext("", "", "203.0.113.20"), &grpcv1.UpsertManagementSettingsRequest{
			Issuer:             "https://auth.example.com",
			Audience:           "leshy-controller",
			JwksUrl:            "https://auth.example.com/jwks.json",
			RequiredScope:      "allow:write",
			GuardedPortsRange:  "3389-3391",
			Iface:              "eth0",
			HandshakeWindowSec: 600,
			InactiveTimerSec:   300,
		})
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("code = %v, want %v", status.Code(err), codes.Unauthenticated)
		}
	})

	t.Run("get settings not found", func(t *testing.T) {
		t.Parallel()

		api := New(Deps{
			Management: &managementUseCaseStub{
				authorizeAllowFn: func(context.Context, string) error { return nil },
				getFn: func(context.Context) (management.StoredSettings, error) {
					return management.StoredSettings{}, management.ErrSettingsNotFound
				},
			},
		})

		_, err := api.GetSettings(incomingContext("Bearer token", "", "203.0.113.21"), &emptypb.Empty{})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("code = %v, want %v", status.Code(err), codes.NotFound)
		}
	})

	t.Run("block unavailable when filter runtime not configured", func(t *testing.T) {
		t.Parallel()

		filterStub := &filterUseCaseStub{
			blockFn: func(context.Context) (filter.FlushResult, error) {
				return filter.FlushResult{}, filter.ErrNotConfigured
			},
		}
		managementStub := &managementUseCaseStub{
			authorizeAllowFn: func(context.Context, string) error { return nil },
		}
		api := New(Deps{
			Filter:     filterStub,
			Management: managementStub,
		})

		_, err := api.Block(incomingContext("Bearer token", "", "203.0.113.22"), &emptypb.Empty{})
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want %v", status.Code(err), codes.Unavailable)
		}
	})
}

func incomingContext(authHeader string, bootstrapHeader string, ip string) context.Context {
	ctx := context.Background()
	md := metadata.New(map[string]string{})
	if authHeader != "" {
		md.Set(authorizationMetadataKey, authHeader)
	}
	if bootstrapHeader != "" {
		md.Set(bootstrapMetadataKey, bootstrapHeader)
	}
	ctx = metadata.NewIncomingContext(ctx, md)

	if parsedIP := net.ParseIP(ip); parsedIP != nil {
		ctx = peer.NewContext(ctx, &peer.Peer{
			Addr: &net.TCPAddr{
				IP:   parsedIP,
				Port: 43210,
			},
		})
	}

	return ctx
}
