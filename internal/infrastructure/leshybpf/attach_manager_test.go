package leshybpf

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
)

func TestPinMapSpecs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		maps    map[string]*ebpf.MapSpec
		hasLogs bool
	}{
		{
			name: "pin required maps and logs",
			maps: map[string]*ebpf.MapSpec{
				PendingSrcMapName:    new(ebpf.MapSpec),
				ActiveFlowsMapName:   new(ebpf.MapSpec),
				StatsMapName:         new(ebpf.MapSpec),
				GuardedPortsMapName:  new(ebpf.MapSpec),
				RuntimeConfigMapName: new(ebpf.MapSpec),
				LogsMapName:          new(ebpf.MapSpec),
			},
			hasLogs: true,
		},
		{
			name: "pin required maps without logs",
			maps: map[string]*ebpf.MapSpec{
				PendingSrcMapName:    new(ebpf.MapSpec),
				ActiveFlowsMapName:   new(ebpf.MapSpec),
				StatsMapName:         new(ebpf.MapSpec),
				GuardedPortsMapName:  new(ebpf.MapSpec),
				RuntimeConfigMapName: new(ebpf.MapSpec),
			},
			hasLogs: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spec := &ebpf.CollectionSpec{Maps: tt.maps}
			pinMapSpecs(spec)

			required := []string{
				PendingSrcMapName,
				ActiveFlowsMapName,
				StatsMapName,
				GuardedPortsMapName,
				RuntimeConfigMapName,
			}
			for _, mapName := range required {
				if spec.Maps[mapName].Pinning != ebpf.PinByName {
					t.Fatalf("map %s pinning = %v, want %v", mapName, spec.Maps[mapName].Pinning, ebpf.PinByName)
				}
			}

			if tt.hasLogs && spec.Maps[LogsMapName].Pinning != ebpf.PinByName {
				t.Fatalf("logs map pinning = %v, want %v", spec.Maps[LogsMapName].Pinning, ebpf.PinByName)
			}
		})
	}
}

func TestResolveCoreMaps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		maps    map[string]*ebpf.Map
		wantErr bool
	}{
		{
			name: "all maps found",
			maps: map[string]*ebpf.Map{
				PendingSrcMapName:   new(ebpf.Map),
				GuardedPortsMapName: new(ebpf.Map),
				StatsMapName:        new(ebpf.Map),
				ActiveFlowsMapName:  new(ebpf.Map),
			},
			wantErr: false,
		},
		{
			name: "guarded map missing",
			maps: map[string]*ebpf.Map{
				PendingSrcMapName:  new(ebpf.Map),
				StatsMapName:       new(ebpf.Map),
				ActiveFlowsMapName: new(ebpf.Map),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			coll := &ebpf.Collection{
				Maps: tt.maps,
			}

			var pendingMap, guardedPortsMap, statsMap, activeFlowsMap *ebpf.Map
			err := resolveCoreMaps(
				coll,
				&pendingMap,
				&guardedPortsMap,
				&statsMap,
				&activeFlowsMap,
			)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if pendingMap != tt.maps[PendingSrcMapName] {
				t.Fatal("pending map mismatch")
			}
			if guardedPortsMap != tt.maps[GuardedPortsMapName] {
				t.Fatal("guarded ports map mismatch")
			}
			if statsMap != tt.maps[StatsMapName] {
				t.Fatal("stats map mismatch")
			}
			if activeFlowsMap != tt.maps[ActiveFlowsMapName] {
				t.Fatal("active flows map mismatch")
			}
		})
	}
}

func TestResolveProgram(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		programs  map[string]*ebpf.Program
		progName  string
		wantErr   bool
		wantMatch bool
	}{
		{
			name: "program exists",
			programs: map[string]*ebpf.Program{
				ProgramName: new(ebpf.Program),
			},
			progName:  ProgramName,
			wantErr:   false,
			wantMatch: true,
		},
		{
			name: "program missing",
			programs: map[string]*ebpf.Program{
				"other": new(ebpf.Program),
			},
			progName: ProgramName,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			coll := &ebpf.Collection{
				Programs: tt.programs,
			}

			prog, err := resolveProgram(coll, tt.progName)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantMatch && prog != tt.programs[tt.progName] {
				t.Fatal("program pointer mismatch")
			}
		})
	}
}

func TestRunDebugDiagnostics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		debug bool
	}{
		{
			name:  "debug disabled skips diagnostics",
			debug: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := runDebugDiagnostics(context.Background(), tt.debug, "eth0", "/sys/fs/bpf")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
