package leshybpf

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

// InsertPendingSrcPort inserts an IP+port into the pending map with expiration.
func InsertPendingSrcPort(m *ebpf.Map, ip net.IP, port uint16, window time.Duration) error {
	ip4 := ip.To4()
	if ip4 == nil {
		return fmt.Errorf("not an IPv4 address: %s", ip)
	}

	portNetwork := hostToNetworkPort(port)

	// ключ в network byte order (big-endian): ipv4(4) + port(2) + pad(2)
	keyBytes := make([]byte, 8)                                             //nolint:mnd
	binary.BigEndian.PutUint32(keyBytes[0:4], binary.BigEndian.Uint32(ip4)) // IP in network order
	binary.BigEndian.PutUint16(keyBytes[4:6], portNetwork)                  // port in network order
	binary.BigEndian.PutUint16(keyBytes[6:8], 0)                            // pad

	expiry := getExpiryUint64(window)
	valueBytes := make([]byte, 8) //nolint:mnd
	binary.LittleEndian.PutUint64(valueBytes, expiry)

	log.Info().Msgf("inserting authorization: IP=%s, Port=%d (network: %d), Expires=%s",
		ip, port, portNetwork, time.Now().Add(window).Format(time.RFC3339))
	log.Debug().Msgf("  key bytes in network byte order (big-endian): %x", keyBytes)

	// Linux: bpf_attr for MAP_UPDATE_ELEM
	type bpfAttrMapUpdateElem struct {
		MapFD uint32
		_     uint32
		Key   uint64
		Value uint64
		Flags uint64
	}

	mapFD32, err := getMapFDUint32(m.FD())
	if err != nil {
		return fmt.Errorf("getMapFDUint32: %w", err)
	}
	attr := bpfAttrMapUpdateElem{
		MapFD: mapFD32,
		Key:   uint64(uintptr(unsafe.Pointer(&keyBytes[0]))),
		Value: uint64(uintptr(unsafe.Pointer(&valueBytes[0]))),
		Flags: 0,
	}

	_, _, errno := unix.Syscall(
		unix.SYS_BPF,
		2, //nolint:mnd // BPF_MAP_UPDATE_ELEM
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return fmt.Errorf("bpf syscall failed: %w (errno: %w)", errno, errno)
	}

	log.Debug().Msg("  ✓ key written to map via direct bpf() syscall")

	type bpfAttrMapLookupElem struct {
		MapFD uint32
		_     uint32
		Key   uint64
		Value uint64
	}

	readValueBytes := make([]byte, 8) //nolint:mnd
	readAttr := bpfAttrMapLookupElem{
		MapFD: mapFD32,
		Key:   uint64(uintptr(unsafe.Pointer(&keyBytes[0]))),
		Value: uint64(uintptr(unsafe.Pointer(&readValueBytes[0]))),
	}

	_, _, readErrno := unix.Syscall(
		unix.SYS_BPF, // ex 321
		1,            // BPF_MAP_LOOKUP_ELEM
		uintptr(unsafe.Pointer(&readAttr)),
		unsafe.Sizeof(readAttr),
	)

	if readErrno == 0 {
		readSaddr := binary.BigEndian.Uint32(keyBytes[0:4])
		readDport := binary.BigEndian.Uint16(keyBytes[4:6])
		log.Debug().Msgf("  ✓ parsed from bytes: saddr=0x%08X (%d), dport=0x%04X (%d)",
			readSaddr, readSaddr, readDport, readDport)
	} else {
		log.Debug().Msgf("  ⚠ WARNING: failed to read back via syscall: errno=%d", readErrno)
	}

	// diagnostics via cilium/ebpf
	var readValue uint64
	if err := m.Lookup(keyBytes, &readValue); err != nil {
		log.Debug().Msgf("  ⚠ WARNING: failed to read back via cilium/ebpf: %v", err)
	} else {
		log.Debug().Msgf("  ✓ verified via cilium/ebpf: key exists, value=%d", readValue)
	}

	return nil
}
