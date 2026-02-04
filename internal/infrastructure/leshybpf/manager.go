package leshybpf

import (
	"github.com/cilium/ebpf"
)

type Manager struct {
	coll *ebpf.Collection

	Pending     *ebpf.Map
	Guarded     *ebpf.Map
	Stats       *ebpf.Map
	ActiveFlows *ebpf.Map
	Program     *ebpf.Program
}

// Close releases collection.
func (m *Manager) Close() error {
	if m == nil || m.coll == nil {
		return nil
	}
	m.coll.Close()
	m.coll = nil

	return nil
}

type AttachResult struct {
	PendingMap      *ebpf.Map
	GuardedPortsMap *ebpf.Map
	StatsMap        *ebpf.Map
	ActiveFlowsMap  *ebpf.Map
}
