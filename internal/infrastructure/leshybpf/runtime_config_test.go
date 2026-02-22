package leshybpf

import (
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func newRuntimeConfigMap(t *testing.T) *ebpf.Map {
	t.Helper()

	spec := &ebpf.MapSpec{
		Name:       "test_runtime_cfg",
		Type:       ebpf.Array,
		KeySize:    4, // uint32
		ValueSize:  8, // uint64
		MaxEntries: 1,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("cannot create ebpf map in this environment: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	return m
}

func TestSetInactiveTimerSec(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		timerSec  int
		wantErr   bool
		wantValue uint64
	}{
		{
			name:     "invalid zero timer",
			timerSec: 0,
			wantErr:  true,
		},
		{
			name:      "valid timer",
			timerSec:  300,
			wantErr:   false,
			wantValue: uint64(300 * time.Second),
		},
		{
			name:      "overwrite timer",
			timerSec:  120,
			wantErr:   false,
			wantValue: uint64(120 * time.Second),
		},
	}

	m := newRuntimeConfigMap(t)
	key := uint32(0)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetInactiveTimerSec(m, tt.timerSec)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var got uint64
			if lookupErr := m.Lookup(&key, &got); lookupErr != nil {
				t.Fatalf("lookup runtime config: %v", lookupErr)
			}
			if got != tt.wantValue {
				t.Fatalf("runtime config value = %d, want %d", got, tt.wantValue)
			}
		})
	}
}

func TestSetRuntimeInactiveAllowNS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		value     uint64
		useNilMap bool
		wantErr   bool
	}{
		{
			name:      "nil map",
			value:     1,
			useNilMap: true,
			wantErr:   true,
		},
		{
			name:      "zero value",
			value:     0,
			useNilMap: false,
			wantErr:   true,
		},
		{
			name:      "valid value",
			value:     uint64(42 * time.Second),
			useNilMap: false,
			wantErr:   false,
		},
	}

	key := uint32(0)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var m *ebpf.Map
			if !tt.useNilMap {
				m = newRuntimeConfigMap(t)
			}

			err := setRuntimeInactiveAllowNS(m, tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			var got uint64
			if lookupErr := m.Lookup(&key, &got); lookupErr != nil {
				t.Fatalf("lookup runtime config: %v", lookupErr)
			}
			if got != tt.value {
				t.Fatalf("runtime config value = %d, want %d", got, tt.value)
			}
		})
	}
}
