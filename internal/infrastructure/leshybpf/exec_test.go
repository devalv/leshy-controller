package leshybpf

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func requireCmd(t *testing.T, name string) {
	t.Helper()
	if _, err := exec.LookPath(name); err != nil {
		t.Skipf("command %q not found in PATH: %v", name, err)
	}
}

func TestRunCmd_Success_ReturnsStdout(t *testing.T) {
	t.Parallel()
	requireCmd(t, "sh")

	out, err := runCmd(context.Background(), commandShell, "-c", "printf 'ok'")
	if err != nil {
		t.Fatalf("expected nil error, got %v (out=%q)", err, string(out))
	}
	if string(out) != "ok" {
		t.Fatalf("unexpected output: got %q want %q", string(out), "ok")
	}
}

func TestRunCmd_NonZeroExit_ReturnsErrorAndStderr(t *testing.T) {
	t.Parallel()
	requireCmd(t, "sh")

	// stderr + exit 2
	out, err := runCmd(context.Background(), commandShell, "-c", "echo 'boom' 1>&2; exit 2")
	if err == nil {
		t.Fatalf("expected error, got nil (out=%q)", string(out))
	}

	// Обычно это *exec.ExitError, но мы не завязываемся на конкретный тип
	if !strings.Contains(string(out), "boom") {
		t.Fatalf("expected stderr to contain %q, got out=%q", "boom", string(out))
	}
}

func TestRunCmd_Timeout_KillsProcess(t *testing.T) {
	t.Parallel()
	requireCmd(t, "sleep")

	ctx := context.Background()

	_, err := runCmd(ctx, commandSleep, "10")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}

	// В зависимости от ОС/версии Go это может быть:
	// - context deadline exceeded
	// - signal: killed
	// - exit status ...
	// Мы принимаем любой вариант, главное — что команда не “успешна”.
	if errors.Is(err, context.DeadlineExceeded) {
		return
	}

	// Частый кейс: Go убил процесс и вернул ошибку завершения
	// Формат обычно "signal: killed" (Linux) или похожее.
	msg := err.Error()
	if strings.Contains(msg, "signal: killed") ||
		strings.Contains(msg, "killed") ||
		strings.Contains(msg, "terminated") {
		return
	}

	t.Fatalf("unexpected error for timeout: %v", err)
}

func TestStartCmd_CancelStopsProcess(t *testing.T) {
	t.Parallel()
	requireCmd(t, "sh")

	cmd, cancel, err := startCmd(context.Background(), commandShell, "-c", "sleep 10")
	if err != nil {
		t.Fatalf("failed to prepare command: %v", err)
	}
	t.Cleanup(func() { cancel() })

	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatalf("failed to start cmd: %v", err)
	}

	// Даём процессу реально стартануть
	time.Sleep(50 * time.Millisecond)

	// Отменяем контекст -> процесс должен быть убит
	cancel()

	startWait := time.Now()
	err = cmd.Wait()
	elapsed := time.Since(startWait)

	if err == nil {
		t.Fatalf("expected error after cancel, got nil")
	}

	// Варианты: context deadline/canceled или exit error из-за kill.
	// cancel() вызывает cancel контекста, поэтому ожидаем context.Canceled
	if !errors.Is(err, context.Canceled) && !strings.Contains(strings.ToLower(err.Error()), "signal") {
		// просто фиксируем, что это действительно ошибка, а не "успех"
		t.Logf("wait error after cancel: %v", err)
	}

	if elapsed > 1500*time.Millisecond {
		t.Fatalf("process did not stop quickly after cancel: elapsed=%v", elapsed)
	}
}

func TestStartCmd_TimeoutStopsProcessEvenWithoutCancel(t *testing.T) {
	t.Parallel()
	requireCmd(t, "sh")

	cmd, cancel, err := startCmd(context.Background(), commandShell, "-c", "sleep 10")
	if err != nil {
		t.Fatalf("failed to prepare command: %v", err)
	}
	defer cancel() // освобождаем ресурсы таймера/контекста

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start cmd: %v", err)
	}

	startWait := time.Now()
	err = cmd.Wait()
	elapsed := time.Since(startWait)

	if err == nil {
		t.Fatalf("expected timeout-related error, got nil")
	}

	// Должно завершиться примерно за cmdTimeout (+ запас)
	if elapsed > cmdTimeout+1500*time.Millisecond {
		t.Fatalf("process did not stop by timeout fast enough: elapsed=%v timeout=%v", elapsed, cmdTimeout)
	}
}

func TestRunCmd_UnsupportedCommand_ReturnsError(t *testing.T) {
	t.Parallel()

	_, err := runCmd(context.Background(), systemCommand(0))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported system command") {
		t.Fatalf("unexpected error: %v", err)
	}
}
