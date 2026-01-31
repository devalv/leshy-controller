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
	// cleanup tc qdisc
	log.Info().Msgf("cleaning up old TC filters and maps for interface %s", iface)
	cmd := exec.Command("tc", "qdisc", "del", "dev", iface, "clsact") //nolint:noctx
	_ = cmd.Run()                                                     // игнорируем ошибку

	// remove old pinned program
	oldProgPath := bpfPinPath + "/" + PinnedProgRel
	if err := os.Remove(oldProgPath); err == nil {
		log.Info().Msgf("removed old pinned program: %s", oldProgPath)
	}

	// remove old pinned maps
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
			log.Info().Msgf("removed old pinned map: %s", mapPath)
		}
	}

	// optional heavy cleanup via bpftool (оставляем как есть)
	cleanupOldProgramsViaBPFTool()

	spec, err := ebpf.LoadCollectionSpec(bpfProgramPath)
	if err != nil {
		return fmt.Errorf("loading BPF collection spec: %w", err)
	}

	// pinning by name
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

	// pin program
	progPinFile := bpfPinPath + "/" + PinnedProgRel
	if err := prog.Pin(progPinFile); err != nil {
		if !os.IsExist(err) {
			log.Warn().Err(err).Msg("failed to pin program")
		} else {
			log.Info().Msgf("program already pinned at %s", progPinFile)
		}
	} else {
		log.Info().Msgf("program pinned at %s", progPinFile)
	}

	// ensure clsact
	cmd = exec.Command("tc", "qdisc", "add", "dev", iface, "clsact") //nolint:noctx
	_ = cmd.Run()

	// attach pinned program to ingress
	cmd = exec.Command("tc", "filter", "replace", "dev", iface, "ingress", "prio", "1", "handle", "1", "bpf", "da", "pinned", progPinFile) //nolint
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		coll.Close()

		return fmt.Errorf("attaching TC filter with pinned program: %w (program must be pinned to use pinned maps)", err)
	}

	log.Debug().Msgf("BPF program loaded and attached to %s ingress (FD: %d)", iface, prog.FD())
	log.Info().Msgf("BPF maps pinned in %s", bpfPinPath)

	// lightweight check
	checkTCFilterAttached(iface)
	testPendingWritable(coll)

	// heavy diagnostics only in debug
	if opts.Debug {
		RunDiagnostics(DiagnosticsOptions{
			Iface:    iface,
			PinPath:  bpfPinPath,
			Program:  ProgramName,
			MapNames: []string{PendingSrcMapName, GuardedPortsMapName, StatsMapName, ActiveFlowsMapName, LogsMapName},
		})
	}

	return nil
}

func cleanupOldProgramsViaBPFTool() {
	log.Info().Msg("cleaning up old BPF programs and maps via bpftool...")
	cmd := exec.Command("bpftool", "prog", "list") //nolint:noctx
	progListOutput, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(progListOutput), "\n")
	for _, line := range lines {
		if strings.Contains(line, ProgramName) {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				progID := strings.TrimSuffix(parts[0], ":")
				log.Info().Msgf("removing old BPF program ID: %s", progID)
				_ = exec.Command("bpftool", "prog", "delete", "id", progID).Run() //nolint
			}
		}
	}
}

func testPendingWritable(coll *ebpf.Collection) {
	pendingMap, ok := coll.Maps[PendingSrcMapName]
	if !ok || pendingMap == nil {
		return
	}

	testKey := IpPortKey{Saddr: 0x01010101, Dport: 0x1234, Pad: 0} //nolint:mnd
	testValue := uint64(time.Now().UnixNano())                     //nolint

	if err := pendingMap.Put(&testKey, &testValue); err != nil {
		log.Warn().Err(err).Msg("  ⚠ WARNING: failed to write test entry to pending map")

		return
	}

	_ = pendingMap.Delete(&testKey)
	log.Info().Msg("  ✓ pending map is writable")
}

func checkTCFilterAttached(iface string) {
	cmd := exec.Command("tc", "filter", "show", "dev", iface, "ingress") //nolint:noctx
	output, err := cmd.Output()
	if err != nil {
		return
	}
	if strings.Contains(string(output), ProgramName) {
		log.Info().Msgf("  ✓ TC filter found on %s ingress", iface)
	} else {
		log.Warn().Msg("  ⚠ WARNING: TC filter not found in tc output")
		log.Warn().Msgf("  tc output: %s", string(output))
	}
}
