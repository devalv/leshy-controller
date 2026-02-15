package leshybpf

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/devalv/leshy-controller/internal/application/filter"
	"github.com/devalv/leshy-controller/internal/application/management"
)

const defaultAttachTimeout = 30 * time.Second

// RuntimeSettingsApplierOptions конфигурирует runtime настройки управления приложения.
type RuntimeSettingsApplierOptions struct {
	BPFPinPath     string
	BPFProgramPath string
	Debug          bool
	AttachTimeout  time.Duration
}

// RuntimeSettingsApplier применяет настройки управления к прикрепленному eBPF runtime.
type RuntimeSettingsApplier struct {
	mu sync.Mutex

	filterRuntime filter.RuntimeConfigurator
	opts          RuntimeSettingsApplierOptions

	manager       *Manager
	pendingMap    *ebpf.Map
	guardedMap    *ebpf.Map
	statsMap      *ebpf.Map
	activeMap     *ebpf.Map
	runtimeCfgMap *ebpf.Map
	currentIface  string
}

// NewRuntimeSettingsApplier создает новый runtime settings applier.
func NewRuntimeSettingsApplier(
	filterRuntime filter.RuntimeConfigurator,
	options RuntimeSettingsApplierOptions,
) *RuntimeSettingsApplier {
	if options.AttachTimeout <= 0 {
		options.AttachTimeout = defaultAttachTimeout
	}

	return &RuntimeSettingsApplier{
		filterRuntime: filterRuntime,
		opts:          options,
	}
}

// Apply при необходимости подключает и применяет настройки runtime к BPF-картам и фильтрующему сервису.
func (a *RuntimeSettingsApplier) Apply(ctx context.Context, settings management.Settings) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.filterRuntime == nil {
		return errors.New("filter runtime configurator is nil")
	}

	if err := a.ensureAttached(ctx, settings.Iface); err != nil {
		return fmt.Errorf("ensure attached manager: %w", err)
	}

	if a.guardedMap == nil || a.pendingMap == nil || a.statsMap == nil || a.activeMap == nil || a.runtimeCfgMap == nil {
		return errors.New("manager maps are not initialized")
	}

	if err := SetInactiveTimerSec(a.runtimeCfgMap, settings.InactiveTimerSec); err != nil {
		return fmt.Errorf("set runtime inactive timer: %w", err)
	}

	if err := InitializeGuardedPorts(settings.GuardedPortsRange, a.guardedMap); err != nil {
		return fmt.Errorf("initialize guarded ports: %w", err)
	}

	backend := NewFilterBackend(a.pendingMap, a.guardedMap, a.statsMap, a.activeMap)
	if err := a.filterRuntime.ConfigureRuntime(
		backend,
		time.Duration(settings.HandshakeWindowSec)*time.Second,
	); err != nil {
		return fmt.Errorf("configure filter runtime: %w", err)
	}

	return nil
}

// Close закрывает прикреплённый manager и высвобождает мапы.
func (a *RuntimeSettingsApplier) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.manager == nil {
		return nil
	}

	err := a.manager.Close()
	a.manager = nil
	a.pendingMap = nil
	a.guardedMap = nil
	a.statsMap = nil
	a.activeMap = nil
	a.runtimeCfgMap = nil
	a.currentIface = ""
	if err != nil {
		return fmt.Errorf("close bpf manager: %w", err)
	}

	return nil
}

// RuntimeStatus сообщает, прикреплен ли в данный момент BPF-менеджер.
func (a *RuntimeSettingsApplier) RuntimeStatus(_ context.Context) management.RuntimeStatus {
	a.mu.Lock()
	defer a.mu.Unlock()

	return management.RuntimeStatus{
		Attached: a.manager != nil,
		Iface:    a.currentIface,
	}
}

func (a *RuntimeSettingsApplier) ensureAttached(ctx context.Context, iface string) error {
	if a.manager != nil && a.currentIface == iface {
		return nil
	}

	attachCtx, cancel := context.WithTimeout(ctx, a.opts.AttachTimeout)
	defer cancel()

	var pendingMap, guardedMap, statsMap, activeMap *ebpf.Map
	manager, err := NewManagerAndAttach(
		attachCtx,
		iface,
		a.opts.BPFPinPath,
		a.opts.BPFProgramPath,
		AttachOptions{Debug: a.opts.Debug},
		&pendingMap,
		&guardedMap,
		&statsMap,
		&activeMap,
	)
	if err != nil {
		return fmt.Errorf("attach manager: %w", err)
	}

	if pendingMap == nil || guardedMap == nil || statsMap == nil || activeMap == nil {
		_ = manager.Close()

		return errors.New("failed to resolve maps from attached manager")
	}
	if manager.coll == nil {
		_ = manager.Close()

		return errors.New("attached manager collection is nil")
	}

	runtimeCfgMap := manager.coll.Maps[RuntimeConfigMapName]
	if runtimeCfgMap == nil {
		_ = manager.Close()

		return errors.New("failed to resolve runtime config map from attached manager")
	}

	if a.manager != nil {
		_ = a.manager.Close()
	}

	a.manager = manager
	a.pendingMap = pendingMap
	a.guardedMap = guardedMap
	a.statsMap = statsMap
	a.activeMap = activeMap
	a.runtimeCfgMap = runtimeCfgMap
	a.currentIface = iface

	return nil
}
