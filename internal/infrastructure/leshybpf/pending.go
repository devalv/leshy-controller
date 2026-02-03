package leshybpf

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"
	"github.com/rs/zerolog/log"
)

// InsertPendingSrcPort inserts an IP+port into the pending map with expiration.
func InsertPendingSrcPort(m *ebpf.Map, ip net.IP, port uint16, window time.Duration) error {
	key, err := pendingKeyPendingSrc(ip, port)
	if err != nil {
		return fmt.Errorf("pendingKeyPendingSrc: %w", err)
	}

	expiry := getExpiryUint64(window)

	log.Info().Msgf("inserting authorization: IP=%s, Port=%d, Expires=%s",
		ip, port, time.Now().Add(window).Format(time.RFC3339))

	// Вставляем через API cilium/ebpf
	if err := m.Put(&key, &expiry); err != nil {
		return fmt.Errorf("failed to insert into BPF map: %w", err)
	}
	log.Debug().Msg("  ✓ key written to map via cilium/ebpf")

	// Проверяем запись
	var readValue uint64
	if err := m.Lookup(&key, &readValue); err != nil {
		log.Warn().Msgf("  ⚠ WARNING: failed to read back: %v", err)
	} else {
		log.Debug().Msgf("  ✓ verified: key for %s:%d exists: %x", ip, port, key)
	}

	return nil
}
