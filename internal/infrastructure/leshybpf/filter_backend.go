package leshybpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/devalv/leshy-controller/internal/application/filter"
	"github.com/rs/zerolog/log"
)

type FilterBackend struct {
	pending *ebpf.Map
	guarded *ebpf.Map
	stats   *ebpf.Map
	active  *ebpf.Map
}

func NewFilterBackend(pending, guarded, stats, active *ebpf.Map) *FilterBackend {
	return &FilterBackend{pending: pending, guarded: guarded, stats: stats, active: active}
}

func (b *FilterBackend) IsPortGuarded(ctx context.Context, port uint16) (bool, error) {
	_ = ctx

	return IsPortGuarded(b.guarded, port), nil
}

func (b *FilterBackend) InsertPending(ctx context.Context, ip net.IP, port uint16, window time.Duration) error {
	_ = ctx

	return InsertPendingSrcPort(b.pending, ip, port, window)
}

func (b *FilterBackend) Stats(ctx context.Context) (filter.Counters, error) {
	_ = ctx

	return readCountersFromStatsMap(b.stats)
}

func (b *FilterBackend) FlushAuthorizations(ctx context.Context) (filter.FlushResult, error) {
	_ = ctx

	pendingRemoved, err := clearPendingEntries(b.pending)
	if err != nil {
		return filter.FlushResult{}, fmt.Errorf("clear pending entries: %w", err)
	}

	activeRemoved, err := clearActiveFlowEntries(b.active)
	if err != nil {
		return filter.FlushResult{}, fmt.Errorf("clear active flow entries: %w", err)
	}

	return filter.FlushResult{
		PendingEntriesRemoved: pendingRemoved,
		ActiveFlowsRemoved:    activeRemoved,
	}, nil
}

func (b *FilterBackend) VerifyPending(ctx context.Context, ip net.IP, port uint16) error {
	_ = ctx

	keyBytes, err := pendingKeyPendingSrc(ip, port)
	if err != nil {
		return fmt.Errorf("build pending key: %w", err)
	}

	var value uint64
	if err := b.pending.Lookup(&keyBytes, &value); err != nil {
		return fmt.Errorf("failed to read back inserted entry %w", err)
	}

	log.Debug().Msgf(
		"verified: entry exists in map, expires at monotonic_ns=%d (epoch_view=%s)",
		value,
		formatNanoTimestamp(value),
	)

	return nil
}

func clearPendingEntries(m *ebpf.Map) (uint64, error) {
	if m == nil {
		return 0, errors.New("pending map is nil")
	}

	keys, err := listPendingMapKeys(m)
	if err != nil {
		return 0, fmt.Errorf("list pending map keys: %w", err)
	}

	return deletePendingMapKeys(m, keys)
}

func listPendingMapKeys(m *ebpf.Map) ([][8]byte, error) {
	var keys [][8]byte
	iter := m.Iterate()
	var key [8]byte
	var value uint64
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending map: %w", err)
	}

	return keys, nil
}

func deletePendingMapKeys(m *ebpf.Map, keys [][8]byte) (uint64, error) {
	var removed uint64
	for _, key := range keys {
		if err := m.Delete(&key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}

			return removed, fmt.Errorf("delete pending key: %w", err)
		}
		removed++
	}

	return removed, nil
}

func clearActiveFlowEntries(m *ebpf.Map) (uint64, error) {
	if m == nil {
		return 0, errors.New("active flows map is nil")
	}

	keys, err := listActiveFlowMapKeys(m)
	if err != nil {
		return 0, fmt.Errorf("list active flow map keys: %w", err)
	}

	return deleteActiveFlowMapKeys(m, keys)
}

func listActiveFlowMapKeys(m *ebpf.Map) ([][16]byte, error) {
	var keys [][16]byte
	iter := m.Iterate()
	var key [16]byte
	var value uint64
	for iter.Next(&key, &value) {
		keys = append(keys, key)
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate active flow map: %w", err)
	}

	return keys, nil
}

func deleteActiveFlowMapKeys(m *ebpf.Map, keys [][16]byte) (uint64, error) {
	var removed uint64
	for _, key := range keys {
		if err := m.Delete(&key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}

			return removed, fmt.Errorf("delete active flow key: %w", err)
		}
		removed++
	}

	return removed, nil
}
