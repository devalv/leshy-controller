package leshybpf

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

const cmdTimeout = 2 * time.Second

type systemCommand uint8

const (
	commandTC systemCommand = iota + 1
	commandBPFTool
	commandShell
	commandSleep
)

func runCmd(ctx context.Context, command systemCommand, args ...string) ([]byte, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()

	cmd, err := newCommand(cmdCtx, command, args...)
	if err != nil {
		return nil, err
	}

	return cmd.CombinedOutput() //nolint:wrapcheck
}

func startCmd(ctx context.Context, command systemCommand, args ...string) (*exec.Cmd, context.CancelFunc, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, cmdTimeout)
	cmd, err := newCommand(cmdCtx, command, args...)
	if err != nil {
		cancel()

		return nil, nil, err
	}

	return cmd, cancel, nil
}

func newCommand(ctx context.Context, command systemCommand, args ...string) (*exec.Cmd, error) {
	switch command {
	case commandTC:
		cmd := exec.CommandContext(ctx, "tc")
		cmd.Args = append([]string{"tc"}, args...)

		return cmd, nil
	case commandBPFTool:
		cmd := exec.CommandContext(ctx, "bpftool")
		cmd.Args = append([]string{"bpftool"}, args...)

		return cmd, nil
	case commandShell:
		cmd := exec.CommandContext(ctx, "sh")
		cmd.Args = append([]string{"sh"}, args...)

		return cmd, nil
	case commandSleep:
		cmd := exec.CommandContext(ctx, "sleep")
		cmd.Args = append([]string{"sleep"}, args...)

		return cmd, nil
	default:
		return nil, fmt.Errorf("unsupported system command: %d", command)
	}
}
