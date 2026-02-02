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

	if opts.Debug {
		if err := cleanupOldProgramsViaBPFTool(ctx); err != nil {
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

	// держим коллекцию в менеджере, чтобы она не была закрыта GC/по ошибке снаружи
	m.coll = coll

	*pendingMap = coll.Maps[PendingSrcMapName]
	*guardedPortsMap = coll.Maps[GuardedPortsMapName]
	*statsMap = coll.Maps[StatsMapName]
	*activeFlowsMap = coll.Maps[ActiveFlowsMapName]

	if *pendingMap == nil || *guardedPortsMap == nil || *statsMap == nil || *activeFlowsMap == nil {
		coll.Close()
		m.coll = nil

		return errors.New("failed to get maps from collection")
	}

	prog := coll.Programs[ProgramName]
	if prog == nil {
		coll.Close()
		m.coll = nil

		return errors.New("l4_filter program not found")
	}

	progPinFile := bpfPinPath + "/" + PinnedProgRel
	if err := prog.Pin(progPinFile); err != nil {
		if !os.IsExist(err) {
			coll.Close()
			m.coll = nil

			return fmt.Errorf("pinning program: %w", err)
		}
		log.Debug().Msgf("program already pinned at %s", progPinFile)
	} else {
		log.Debug().Msgf("program pinned at %s", progPinFile)
	}

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
		coll.Close()
		m.coll = nil

		return fmt.Errorf("attaching TC filter with pinned program: %w (program must be pinned to use pinned maps)", err)
	}

	log.Debug().Msgf("BPF program loaded and attached to %s ingress (FD: %d)", iface, prog.FD())
	log.Debug().Msgf("BPF maps pinned in %s", bpfPinPath)

	if err := checkTCFilterAttached(ctx, iface); err != nil {
		return fmt.Errorf("checking TC filter attached: %w", err)
	}
	if err := testPendingWritable(coll); err != nil {
		return fmt.Errorf("testing pending writable: %w", err)
	}

	if opts.Debug {
		if err := RunDiagnostics(ctx, DiagnosticsOptions{
			Iface:    iface,
			PinPath:  bpfPinPath,
			Program:  ProgramName,
			MapNames: []string{PendingSrcMapName, GuardedPortsMapName, StatsMapName, ActiveFlowsMapName, LogsMapName},
		}); err != nil {
			return fmt.Errorf("running diagnostics: %w", err)
		}
	}

	return nil
}
