package leshybpf

import (
	"context"
	"os/exec"
	"time"
)

const cmdTimeout = 2 * time.Second

func runCmd(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, name, args...)

	return cmd.CombinedOutput() //nolint:wrapcheck
}

func startCmd(ctx context.Context, name string, args ...string) (*exec.Cmd, context.CancelFunc) {
	cmdCtx, cancel := context.WithTimeout(ctx, cmdTimeout)
	cmd := exec.CommandContext(cmdCtx, name, args...)

	return cmd, cancel
}
