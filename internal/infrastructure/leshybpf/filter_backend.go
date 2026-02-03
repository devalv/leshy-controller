package leshybpf

import (
	"context"
	"encoding/binary"
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
}

func NewFilterBackend(pending, guarded, stats *ebpf.Map) *FilterBackend {
	return &FilterBackend{pending: pending, guarded: guarded, stats: stats}
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

func (b *FilterBackend) VerifyPending(ctx context.Context, ip net.IP, port uint16) error {
	_ = ctx

	portNetwork := HostToNetworkPort(port)

	keyBytes := make([]byte, 8) //nolint:mnd
	binary.BigEndian.PutUint32(keyBytes[0:4], binary.BigEndian.Uint32(ip.To4()))
	binary.BigEndian.PutUint16(keyBytes[4:6], portNetwork)
	binary.BigEndian.PutUint16(keyBytes[6:8], 0)

	var value uint64
	if err := b.pending.Lookup(keyBytes, &value); err != nil {
		return fmt.Errorf("failed to read back inserted entry %w", err)
	}

	log.Debug().Msgf(
		"verified: entry exists in map, expires at %s UTC", formatNanoTimestamp(value),
	)

	return nil
}
