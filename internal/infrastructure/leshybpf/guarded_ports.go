package leshybpf

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/rs/zerolog/log"
)

// GetGuardedPorts возвращает список защищаемых портов в HOST BYTE ORDER.
func GetGuardedPorts(m *ebpf.Map) []uint16 {
	var ports []uint16
	iter := m.Iterate()
	var key uint16
	var value uint8

	for iter.Next(&key, &value) {
		ports = append(ports, networkToHostPort(key))
	}

	return ports
}

// IsPortGuarded проверяет находится ли порт в списке защищаемых (NETWORK byte order).
func IsPortGuarded(m *ebpf.Map, port uint16) bool {
	portNetwork := hostToNetworkPort(port)
	var value uint8
	err := m.Lookup(&portNetwork, &value)

	return err == nil
}

func setGuardedPorts(m *ebpf.Map, ports []uint16) error {
	// выполняем предварительную очистку
	iter := m.Iterate()
	var key uint16
	var value uint8
	for iter.Next(&key, &value) {
		if err := m.Delete(&key); err != nil {
			log.Warn().Err(err).Msgf("failed to delete old map %d", &key)
		}
	}

	// добавляем порты в NETWORK BYTE ORDER
	for _, port := range ports {
		portNetwork := hostToNetworkPort(port)
		v := uint8(1)
		if err := m.Put(&portNetwork, &v); err != nil {
			return fmt.Errorf("failed to add port %d (network: %d): %w", port, portNetwork, err)
		}
		log.Debug().Msgf("added guarded port: %d (network byte order: %d)", port, portNetwork)
	}

	return nil
}

// InitializeGuardedPorts инициализует защищаемые порты из диапазона.
func InitializeGuardedPorts(portsRange string, m *ebpf.Map) error {
	ports, err := parsePortRange(portsRange)
	if err != nil {
		return fmt.Errorf("failed to parse port range: %w", err)
	}

	if err := setGuardedPorts(m, ports); err != nil {
		return fmt.Errorf("failed to initialize guarded ports: %w", err)
	}
	log.Info().Msgf("Guarded %d ports: %v", len(ports), portsRange)

	return nil
}

// parsePortRange парсит диапазон портов в формате "start-end".
func parsePortRange(portsRange string) ([]uint16, error) {
	parts := strings.Split(portsRange, "-")
	if len(parts) != 2 { //nolint:mnd
		return nil, fmt.Errorf("invalid port range format: %s", portsRange)
	}

	start, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid start port: %s", parts[0])
	}

	end, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid end port: %s", parts[1])
	}

	var ports []uint16
	for p := start; p <= end; p++ {
		ports = append(ports, uint16(p))
	}

	return ports, nil
}
