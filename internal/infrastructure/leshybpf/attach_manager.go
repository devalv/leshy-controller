package leshybpf

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/rs/zerolog/log"
)

func NewManagerAndAttach(
	ctx context.Context,
	iface, bpfPinPath, bpfProgramPath string,
	opts AttachOptions,
	pendingMap, guardedPortsMap, statsMap, activeFlowsMap **ebpf.Map,
) (*Manager, error) {
	m := &Manager{}
	if err := m.AttachWithOptions(
		ctx,
		iface, bpfPinPath, bpfProgramPath,
		opts,
		pendingMap, guardedPortsMap, statsMap, activeFlowsMap,
	); err != nil {
		return nil, err
	}

	return m, nil
}

func (m *Manager) AttachWithOptions(
	ctx context.Context,
	iface, bpfPinPath, bpfProgramPath string,
	opts AttachOptions,
	pendingMap, guardedPortsMap, statsMap, activeFlowsMap **ebpf.Map,
) error {
	if err := cleanupExistingArtifacts(ctx, iface, bpfPinPath, opts.Debug); err != nil {
		return err
	}

	coll, err := loadPinnedCollection(bpfProgramPath, bpfPinPath)
	if err != nil {
		return err
	}

	// держим коллекцию в менеджере, чтобы она не была закрыта GC/по ошибке снаружи
	m.coll = coll

	if err := resolveCoreMaps(
		coll,
		pendingMap,
		guardedPortsMap,
		statsMap,
		activeFlowsMap,
	); err != nil {
		coll.Close()
		m.coll = nil

		return err
	}

	prog, err := resolveProgram(coll, ProgramName)
	if err != nil {
		coll.Close()
		m.coll = nil

		return err
	}

	progPinFile := bpfPinPath + "/" + PinnedProgRel
	if err := pinProgram(prog, progPinFile); err != nil {
		if !os.IsExist(err) {
			coll.Close()
			m.coll = nil

			return err
		}
		log.Debug().Msgf("program already pinned at %s", progPinFile)
	}

	if err := attachPinnedProgramToTC(ctx, iface, progPinFile); err != nil {
		coll.Close()
		m.coll = nil

		return err
	}

	if err := runPostAttachChecks(ctx, iface, bpfPinPath, coll, prog, opts); err != nil {
		return err
	}

	return nil
}

func loadPinnedCollection(bpfProgramPath, bpfPinPath string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(bpfProgramPath)
	if err != nil {
		return nil, fmt.Errorf("loading BPF collection spec: %w", err)
	}

	pinMapSpecs(spec)

	eco := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: bpfPinPath},
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, eco)
	if err != nil {
		return nil, fmt.Errorf("creating BPF collection: %w", err)
	}

	return coll, nil
}

func resolveCoreMaps(
	coll *ebpf.Collection,
	pendingMap, guardedPortsMap, statsMap, activeFlowsMap **ebpf.Map,
) error {
	*pendingMap = coll.Maps[PendingSrcMapName]
	*guardedPortsMap = coll.Maps[GuardedPortsMapName]
	*statsMap = coll.Maps[StatsMapName]
	*activeFlowsMap = coll.Maps[ActiveFlowsMapName]

	if *pendingMap == nil || *guardedPortsMap == nil || *statsMap == nil || *activeFlowsMap == nil {
		return errors.New("failed to get maps from collection")
	}

	return nil
}

func resolveProgram(coll *ebpf.Collection, programName string) (*ebpf.Program, error) {
	prog := coll.Programs[programName]
	if prog == nil {
		return nil, errors.New("l4_filter program not found")
	}

	return prog, nil
}

func pinProgram(prog *ebpf.Program, progPinFile string) error {
	if err := prog.Pin(progPinFile); err != nil {
		return fmt.Errorf("pinning program: %w", err)
	}

	log.Debug().Msgf("program pinned at %s", progPinFile)

	return nil
}

func attachPinnedProgramToTC(ctx context.Context, iface, progPinFile string) error {
	// tc qdisc add ... clsact
	if out, err := runCmd(ctx, "tc", "qdisc", "add", "dev", iface, "clsact"); err != nil {
		return fmt.Errorf("tc qdisc add clsact: %w: %s", err, string(out))
	}

	// tc filter replace ... pinned <progPinFile>
	cmd, cancel := startCmd(
		ctx,
		"tc",
		"filter",
		"replace",
		"dev",
		iface,
		"ingress",
		"prio",
		"1",
		"handle",
		"1",
		"bpf",
		"da",
		"pinned",
		progPinFile,
	)
	defer cancel()

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf(
			"attaching TC filter with pinned program: %w (program must be pinned to use pinned maps)",
			err,
		)
	}

	return nil
}

func runPostAttachChecks(
	ctx context.Context,
	iface, bpfPinPath string,
	coll *ebpf.Collection,
	prog *ebpf.Program,
	opts AttachOptions,
) error {
	log.Debug().Msgf("BPF program loaded and attached to %s ingress (FD: %d)", iface, prog.FD())
	log.Debug().Msgf("BPF maps pinned in %s", bpfPinPath)

	if err := checkTCFilterAttached(ctx, iface); err != nil {
		return fmt.Errorf("checking TC filter attached: %w", err)
	}
	if err := testPendingWritable(coll); err != nil {
		return fmt.Errorf("testing pending writable: %w", err)
	}

	if err := runDebugDiagnostics(ctx, opts.Debug, iface, bpfPinPath); err != nil {
		return err
	}

	return nil
}

func runDebugDiagnostics(ctx context.Context, debug bool, iface, bpfPinPath string) error {
	if !debug {
		return nil
	}

	if err := RunDiagnostics(ctx, DiagnosticsOptions{
		Iface:    iface,
		PinPath:  bpfPinPath,
		Program:  ProgramName,
		MapNames: []string{PendingSrcMapName, GuardedPortsMapName, StatsMapName, ActiveFlowsMapName, LogsMapName},
	}); err != nil {
		return fmt.Errorf("running diagnostics: %w", err)
	}

	return nil
}

func cleanupExistingArtifacts(ctx context.Context, iface, bpfPinPath string, debug bool) error {
	log.Debug().Msgf("cleaning up old TC filters and maps for interface %s", iface)

	if out, err := runCmd(ctx, "tc", "qdisc", "del", "dev", iface, "clsact"); err != nil {
		// ошибка может быть нормой на чистой системе
		log.Warn().Err(err).Msgf("tc qdisc del clsact: %s", string(out))
	}

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

	if debug {
		if err := cleanupOldProgramsViaBPFTool(ctx); err != nil {
			return fmt.Errorf("cleanup old programs via bpftool: %w", err)
		}
	}

	return nil
}

func pinMapSpecs(spec *ebpf.CollectionSpec) {
	// привязка по имени мап
	spec.Maps[PendingSrcMapName].Pinning = ebpf.PinByName
	spec.Maps[ActiveFlowsMapName].Pinning = ebpf.PinByName
	spec.Maps[StatsMapName].Pinning = ebpf.PinByName
	spec.Maps[GuardedPortsMapName].Pinning = ebpf.PinByName
	if spec.Maps[LogsMapName] != nil {
		spec.Maps[LogsMapName].Pinning = ebpf.PinByName
	}
}
