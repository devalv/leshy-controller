package leshybpf

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/rs/zerolog/log"
)

type AttachOptions struct {
	Debug bool
}

// AttachBPFWithTC загружает и прикрепляет BPF программу к TC.
// возвращает карты из коллекции, чтобы контроллер использовал те же карты, что и программа.
func AttachBPFWithTC(
	ctx context.Context,
	iface, bpfPinPath, bpfProgramPath string,
	pendingMap, guardedPortsMap, statsMap, activeFlowsMap **ebpf.Map,
) error {
	_, err := NewManagerAndAttach(
		ctx,
		iface, bpfPinPath, bpfProgramPath,
		AttachOptions{Debug: false},
		pendingMap, guardedPortsMap, statsMap, activeFlowsMap,
	)

	return err
}

func AttachBPFWithTCWithOptions(
	ctx context.Context,
	iface, bpfPinPath, bpfProgramPath string,
	opts AttachOptions,
	pendingMap, guardedPortsMap, statsMap, activeFlowsMap **ebpf.Map,
) error {
	_, err := NewManagerAndAttach(
		ctx,
		iface, bpfPinPath, bpfProgramPath,
		opts,
		pendingMap, guardedPortsMap, statsMap, activeFlowsMap,
	)

	return err
}

func cleanupOldProgramsViaBPFTool(ctx context.Context) error {
	log.Debug().Msg("cleaning up old BPF programs and maps via bpftool...")
	if !isBpftoolAvailable() {
		log.Warn().Msg("bpftool is not available on the system.")

		return nil
	}

	out, err := runCmd(ctx, "bpftool", "prog", "list")
	if err != nil {
		return fmt.Errorf("failed to list bpf programs with bpftool: %w: %s", err, string(out))
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, ProgramName) {
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}

			progID := strings.TrimSuffix(parts[0], ":")
			log.Debug().Msgf("removing old BPF program ID: %s", progID)

			delOut, delErr := runCmd(ctx, "bpftool", "prog", "delete", "id", progID)
			if delErr != nil {
				return fmt.Errorf("removing old BPF program ID %s: %w: %s", progID, delErr, string(delOut))
			}
		}
	}

	return nil
}

func testPendingWritable(coll *ebpf.Collection) error {
	pendingMap, ok := coll.Maps[PendingSrcMapName]
	if !ok || pendingMap == nil {
		return errors.New("pending map not found")
	}

	testKey := IpPortKey{Saddr: 0x01010101, Dport: 0x1234, Pad: 0} //nolint:mnd
	testValue := getUnixNanoUint64()

	if err := pendingMap.Put(&testKey, &testValue); err != nil {
		return fmt.Errorf("failed to write test entry to pending map: %w", err)
	}

	_ = pendingMap.Delete(&testKey)
	log.Debug().Msg("  ✓ pending map is writable")

	return nil
}

func checkTCFilterAttached(ctx context.Context, iface string) error {
	out, err := runCmd(ctx, "tc", "filter", "show", "dev", iface, "ingress")
	if err != nil {
		return fmt.Errorf("running tc filter show: %w: %s", err, string(out))
	}

	if strings.Contains(string(out), ProgramName) {
		log.Debug().Msgf("  ✓ TC filter found on %s ingress", iface)

		return nil
	}

	return fmt.Errorf("tc filter not found in tc output: %s", string(out))
}
