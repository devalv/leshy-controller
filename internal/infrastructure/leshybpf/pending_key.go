package leshybpf

import (
	"encoding/binary"
	"fmt"
	"net"
)

// pendingKeyPendingSrc строит ключ для l4_pending_src.
// Pending key layout:
// [0:4] IPv4 bytes as in packet (network order bytes)
// [4:6] destination port in little-endian (must match eBPF lookup_key builder)
// [6:8] pad (zeros).
func pendingKeyPendingSrc(ip net.IP, port uint16) ([8]byte, error) {
	ip4 := ip.To4()
	if ip4 == nil {
		return [8]byte{}, fmt.Errorf("not an IPv4 address: %s", ip)
	}

	var key [8]byte
	copy(key[0:4], ip4)
	binary.LittleEndian.PutUint16(key[4:6], port)
	// key[6:8] = 0

	return key, nil
}
