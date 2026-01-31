package leshybpf

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/rs/zerolog/log"
)

// GetGuardedPorts returns the list of guarded ports in HOST BYTE ORDER.
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

// IsPortGuarded checks if a port is in the guarded ports list (uses NETWORK byte order).
func IsPortGuarded(m *ebpf.Map, port uint16) bool {
	portNetwork := hostToNetworkPort(port)
	var value uint8
	err := m.Lookup(&portNetwork, &value)

	return err == nil
}

func setGuardedPorts(m *ebpf.Map, ports []uint16) error {
	// Clear existing ports
	iter := m.Iterate()
	var key uint16
	var value uint8
	for iter.Next(&key, &value) {
		m.Delete(&key) //nolint
	}

	// Add new ports in NETWORK BYTE ORDER
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

// InitializeGuardedPorts initializes guarded ports from port range.
func InitializeGuardedPorts(portsRange string, m *ebpf.Map) {
	ports := parsePortRange(portsRange)
	if err := setGuardedPorts(m, ports); err != nil {
		log.Fatal().Err(err).Msg("failed to initialize guarded ports")
	}
	log.Debug().Msgf("Guarded %d ports: %v", len(ports), portsRange)
}

// parsePortRange parses port range in "start-end" format.
func parsePortRange(portsRange string) []uint16 {
	parts := strings.Split(portsRange, "-")
	if len(parts) != 2 { //nolint:mnd
		log.Error().Msgf("invalid port range format: %s", portsRange)

		return nil
	}

	start, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		log.Error().Err(err).Msgf("invalid start port: %s", parts[0])

		return nil
	}

	end, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		log.Error().Err(err).Msgf("invalid end port: %s", parts[1])

		return nil
	}

	var ports []uint16
	for p := start; p <= end; p++ {
		ports = append(ports, uint16(p))
	}

	return ports
}
