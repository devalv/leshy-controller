package leshybpf

import (
	"encoding/binary"
	"errors"
	"fmt"

	ciliumebpf "github.com/cilium/ebpf"

	"github.com/devalv/leshy-controller/internal/application/filter"
)

func readCountersFromStatsMap(m *ciliumebpf.Map) (filter.Counters, error) {
	if m == nil {
		return filter.Counters{}, errors.New("stats map is nil")
	}

	info, err := m.Info()
	if err != nil {
		return filter.Counters{}, fmt.Errorf("stats map info: %w", err)
	}

	// ожидаем минимум 10 * 8 байт = 80 байт
	if info.ValueSize < 80 { //nolint:mnd
		return filter.Counters{}, fmt.Errorf("invalid stats value size: expected >=80, got %d", info.ValueSize)
	}

	key := uint32(0)
	raw := make([]byte, info.ValueSize)

	// передаем slice (raw), а не указатель на slice
	if err := m.Lookup(&key, raw); err != nil {
		return filter.Counters{}, fmt.Errorf("stats map lookup: %w", err)
	}

	return filter.Counters{
		Allowed:                binary.LittleEndian.Uint64(raw[0:8]),
		Dropped:                binary.LittleEndian.Uint64(raw[8:16]),
		SYNAllowed:             binary.LittleEndian.Uint64(raw[16:24]),
		SYNDropped:             binary.LittleEndian.Uint64(raw[24:32]),
		ActiveFlowHits:         binary.LittleEndian.Uint64(raw[32:40]),
		PendingPromotions:      binary.LittleEndian.Uint64(raw[40:48]),
		PendingExpiredCleanups: binary.LittleEndian.Uint64(raw[48:56]),
		IPPortAuthHits:         binary.LittleEndian.Uint64(raw[56:64]),
		NonGuardedPortAllowed:  binary.LittleEndian.Uint64(raw[64:72]),
		GuardedPortDropped:     binary.LittleEndian.Uint64(raw[72:80]),
	}, nil
}
