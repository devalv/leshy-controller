package leshybpf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/rs/zerolog/log"
)

type AttachOptions struct {
	Debug bool
}

// AttachBPFWithTC загружает и прикрепляет BPF программу к TC.
// Возвращает карты из коллекции, чтобы контроллер использовал те же карты, что и программа.
func AttachBPFWithTC(iface, bpfPinPath, bpfProgramPath string,
	pendingMap, guardedPortsMap, statsMap, activeFlowsMap **ebpf.Map,
) error {
	return AttachBPFWithTCWithOptions(
		iface, bpfPinPath, bpfProgramPath,
		AttachOptions{Debug: false},
		pendingMap, guardedPortsMap, statsMap, activeFlowsMap,
	)
}

func AttachBPFWithTCWithOptions( //nolint
	iface, bpfPinPath, bpfProgramPath string,
	opts AttachOptions,
	pendingMap, guardedPortsMap, statsMap, activeFlowsMap **ebpf.Map,
) error {
	log.Debug().Msgf("cleaning up old TC filters and maps for interface %s", iface)
	cmd := exec.Command("tc", "qdisc", "del", "dev", iface, "clsact") //nolint:noctx
	_ = cmd.Run()                                                     // TODO: обработать ошибку

	oldProgPath := bpfPinPath + "/" + PinnedProgRel
	if err := os.Remove(oldProgPath); err == nil {
		log.Debug().Msgf("removed old pinned program: %s", oldProgPath)
	}

	oldMaps := []string{
		PendingSrcMapName,
		GuardedPortsMapName,
		StatsMapName,
		ActiveFlowsMapName,
		LogsMapName,
	}
	for _, mapName := range oldMaps {
		mapPath := fmt.Sprintf("%s/%s", bpfPinPath, mapName)
		if err := os.Remove(mapPath); err == nil {
			log.Debug().Msgf("removed old pinned map: %s", mapPath)
		}
	}

	if opts.Debug {
		err := cleanupOldProgramsViaBPFTool()
		if err != nil {
			return fmt.Errorf("cleanup old programs via bpftool: %w", err)
		}
	}

	spec, err := ebpf.LoadCollectionSpec(bpfProgramPath)
	if err != nil {
		return fmt.Errorf("loading BPF collection spec: %w", err)
	}

	// привязка по имени мап
	spec.Maps[PendingSrcMapName].Pinning = ebpf.PinByName
	spec.Maps[ActiveFlowsMapName].Pinning = ebpf.PinByName
	spec.Maps[StatsMapName].Pinning = ebpf.PinByName
	spec.Maps[GuardedPortsMapName].Pinning = ebpf.PinByName
	if spec.Maps[LogsMapName] != nil {
		spec.Maps[LogsMapName].Pinning = ebpf.PinByName
	}

	eco := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfPinPath},
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, eco)
	if err != nil {
		return fmt.Errorf("creating BPF collection: %w", err)
	}
	bpfCollection = coll

	*pendingMap = coll.Maps[PendingSrcMapName]
	*guardedPortsMap = coll.Maps[GuardedPortsMapName]
	*statsMap = coll.Maps[StatsMapName]
	*activeFlowsMap = coll.Maps[ActiveFlowsMapName]

	if *pendingMap == nil || *guardedPortsMap == nil || *statsMap == nil || *activeFlowsMap == nil {
		coll.Close()

		return errors.New("failed to get maps from collection")
	}

	prog := coll.Programs[ProgramName]
	if prog == nil {
		coll.Close()
		bpfCollection = nil

		return errors.New("l4_filter program not found")
	}

	progPinFile := bpfPinPath + "/" + PinnedProgRel
	if err := prog.Pin(progPinFile); err != nil {
		if !os.IsExist(err) {
			return fmt.Errorf("pinning program: %w", err)
		} else {
			log.Debug().Msgf("program already pinned at %s", progPinFile)
		}
	} else {
		log.Debug().Msgf("program pinned at %s", progPinFile)
	}

	// привязываем дисциплину очереди для фильтрации на интерфейсе
	cmd = exec.Command("tc", "qdisc", "add", "dev", iface, "clsact") //nolint:noctx
	_ = cmd.Run()                                                    // TODO: обработать ошибку

	// прикрепляем bpf-программу (мапу) для фильтрации трафика на интерфейсе
	cmd = exec.Command("tc", "filter", "replace", "dev", iface, "ingress", "prio", "1", "handle", "1", "bpf", "da", "pinned", progPinFile) //nolint
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		coll.Close()

		return fmt.Errorf("attaching TC filter with pinned program: %w (program must be pinned to use pinned maps)", err)
	}

	log.Debug().Msgf("BPF program loaded and attached to %s ingress (FD: %d)", iface, prog.FD())
	log.Debug().Msgf("BPF maps pinned in %s", bpfPinPath)

	err = checkTCFilterAttached(iface)
	if err != nil {
		return fmt.Errorf("checking TC filter attached: %w", err)
	}
	err = testPendingWritable(coll)
	if err != nil {
		return fmt.Errorf("testing pending writable: %w", err)
	}

	if opts.Debug {
		err := RunDiagnostics(DiagnosticsOptions{
			Iface:    iface,
			PinPath:  bpfPinPath,
			Program:  ProgramName,
			MapNames: []string{PendingSrcMapName, GuardedPortsMapName, StatsMapName, ActiveFlowsMapName, LogsMapName},
		})
		if err != nil {
			return fmt.Errorf("running diagnostics: %w", err)
		}
	}

	return nil
}

func cleanupOldProgramsViaBPFTool() error {
	log.Debug().Msg("cleaning up old BPF programs and maps via bpftool...")
	if !isBpftoolAvailable() {
		log.Warn().Msg("bpftool is not available on the system.")

		return nil
	}

	cmd := exec.Command("bpftool", "prog", "list") //nolint:noctx
	progListOutput, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to list bpf programs with bpftool: %w", err)
	}

	lines := strings.Split(string(progListOutput), "\n") // TODO: not optimal
	for _, line := range lines {
		if strings.Contains(line, ProgramName) {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				progID := strings.TrimSuffix(parts[0], ":")
				log.Debug().Msgf("removing old BPF program ID: %s", progID)
				err = exec.Command("bpftool", "prog", "delete", "id", progID).Run() //nolint
				if err != nil {
					return fmt.Errorf("removing old BPF program ID %s: %w", progID, err)
				}
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
	testValue := uint64(time.Now().UnixNano())                     //nolint

	if err := pendingMap.Put(&testKey, &testValue); err != nil {
		return fmt.Errorf("failed to write test entry to pending map: %w", err)
	}

	_ = pendingMap.Delete(&testKey)
	log.Debug().Msg("  ✓ pending map is writable")

	return nil
}

func checkTCFilterAttached(iface string) error {
	cmd := exec.Command("tc", "filter", "show", "dev", iface, "ingress") //nolint:noctx
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("running tc filter show: %w", err)
	}
	if strings.Contains(string(output), ProgramName) {
		log.Debug().Msgf("  ✓ TC filter found on %s ingress", iface)
	} else {
		return fmt.Errorf("  ⚠ WARNING: TC filter not found in tc output      tc output: %s", string(output))
	}

	return nil
}
