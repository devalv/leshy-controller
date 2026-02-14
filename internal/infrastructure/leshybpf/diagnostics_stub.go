//go:build !linux

package leshybpf

import "context"

// DiagnosticsOptions carries optional diagnostic settings for debug mode.
type DiagnosticsOptions struct {
	Iface    string
	PinPath  string
	Program  string
	MapNames []string
}

// RunDiagnostics is a no-op outside Linux.
func RunDiagnostics(_ context.Context, _ DiagnosticsOptions) error {
	return nil
}

func isBpftoolAvailable() bool {
	return false
}
