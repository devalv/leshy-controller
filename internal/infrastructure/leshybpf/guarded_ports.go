package leshybpf

import (
	"fmt"
	"math"
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

	start, err := parsePort(parts[0], "start")
	if err != nil {
		return nil, err
	}

	end, err := parsePort(parts[1], "end")
	if err != nil {
		return nil, err
	}

	if start > end {
		return nil, fmt.Errorf("invalid port range: start %d is greater than end %d", start, end)
	}

	portsCount := int(end-start) + 1
	if portsCount > int(GuardedPortsMax) {
		return nil, fmt.Errorf(
			"port range contains %d ports, maximum supported is %d",
			portsCount,
			GuardedPortsMax,
		)
	}

	ports := make([]uint16, 0, portsCount)
	for p := start; ; p++ {
		ports = append(ports, p)
		if p == end {
			break
		}
	}

	return ports, nil
}

func parsePort(rawValue, fieldName string) (uint16, error) {
	value, err := strconv.ParseUint(rawValue, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid %s port: %s", fieldName, rawValue)
	}
	if value > math.MaxUint16 {
		return 0, fmt.Errorf("invalid %s port: %s", fieldName, rawValue)
	}

	return uint16(value), nil
}
