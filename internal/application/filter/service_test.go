package filter

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

type backendStub struct {
	isGuardedFn func(ctx context.Context, port uint16) (bool, error)
	insertFn    func(ctx context.Context, ip net.IP, port uint16, window time.Duration) error
	statsFn     func(ctx context.Context) (Counters, error)
	verifyFn    func(ctx context.Context, ip net.IP, port uint16) error
}

func (s *backendStub) IsPortGuarded(ctx context.Context, port uint16) (bool, error) {
	if s.isGuardedFn == nil {
		return true, nil
	}

	return s.isGuardedFn(ctx, port)
}

func (s *backendStub) InsertPending(ctx context.Context, ip net.IP, port uint16, window time.Duration) error {
	if s.insertFn == nil {
		return nil
	}

	return s.insertFn(ctx, ip, port, window)
}

func (s *backendStub) Stats(ctx context.Context) (Counters, error) {
	if s.statsFn == nil {
		return Counters{}, nil
	}

	return s.statsFn(ctx)
}

func (s *backendStub) VerifyPending(ctx context.Context, ip net.IP, port uint16) error {
	if s.verifyFn == nil {
		return nil
	}

	return s.verifyFn(ctx, ip, port)
}

func TestServiceConfigureRuntime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		backend Backend
		window  time.Duration
		wantErr bool
	}{
		{
			name:    "nil backend",
			backend: nil,
			window:  10 * time.Second,
			wantErr: true,
		},
		{
			name:    "non positive window",
			backend: &backendStub{},
			window:  0,
			wantErr: true,
		},
		{
			name:    "success",
			backend: &backendStub{},
			window:  10 * time.Second,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			service := New(nil, Options{})
			err := service.ConfigureRuntime(tt.backend, tt.window)
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestServiceAllowRequiresRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	service := New(nil, Options{})
	_, err := service.Allow(context.Background(), net.ParseIP("127.0.0.1"), 3389)
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestServiceAllowUsesConfiguredWindow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.February, 11, 12, 0, 0, 0, time.UTC)
	var gotWindow time.Duration

	service := New(nil, Options{
		Now: func() time.Time {
			return now
		},
	})
	err := service.ConfigureRuntime(&backendStub{
		insertFn: func(_ context.Context, _ net.IP, _ uint16, window time.Duration) error {
			gotWindow = window

			return nil
		},
	}, 30*time.Second)
	if err != nil {
		t.Fatalf("configure runtime: %v", err)
	}

	expires, err := service.Allow(context.Background(), net.ParseIP("127.0.0.1"), 3389)
	if err != nil {
		t.Fatalf("allow: %v", err)
	}
	if gotWindow != 30*time.Second {
		t.Fatalf("window = %s, want %s", gotWindow, 30*time.Second)
	}
	if !expires.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("expires = %s, want %s", expires, now.Add(30*time.Second))
	}
}

func TestServiceStatsRequiresRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	service := New(nil, Options{})
	_, err := service.Stats(context.Background())
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}
