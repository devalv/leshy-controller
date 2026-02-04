package leshybpf

import (
	"encoding/binary"
	"testing"
)

func TestHostToNetworkPort_MatchesBigEndianEncoding(t *testing.T) {
	t.Parallel()

	// набор типовых значений, включая границы и “смешанные” байты
	tests := []uint16{
		0x0000,
		0x0001,
		0x0010,
		0x00FF,
		0x0100,
		0x1234,
		0xABCD,
		0xFF00,
		0xFFFF,
	}

	for _, p := range tests {
		p := p
		t.Run("value", func(t *testing.T) {
			t.Parallel()

			// “Эталон”: если на хосте порт = p, то network order bytes = BigEndian(p)
			var b [2]byte
			binary.BigEndian.PutUint16(b[:], p)
			want := binary.LittleEndian.Uint16(b[:]) // как будет лежать uint16 в памяти little-endian хоста

			got := HostToNetworkPort(p)
			if got != want {
				t.Fatalf("HostToNetworkPort mismatch for 0x%04X: got=0x%04X want=0x%04X", p, got, want)
			}
		})
	}
}

func TestHostNetwork_Roundtrip(t *testing.T) {
	t.Parallel()

	tests := []uint16{
		0,
		1,
		80,
		443,
		8080,
		65535,
		0x1234,
		0xBEEF,
	}

	for _, p := range tests {
		p := p
		t.Run("roundtrip", func(t *testing.T) {
			t.Parallel()

			n := HostToNetworkPort(p)
			back := networkToHostPort(n)
			if back != p {
				t.Fatalf("roundtrip failed: p=%d (0x%04X) -> n=0x%04X -> back=%d (0x%04X)",
					p, p, n, back, back)
			}
		})
	}
}

func TestNetworkToHostPort_SameAsHostToNetworkPort(t *testing.T) {
	t.Parallel()

	// Тест фиксирует контракт: обе функции эквивалентны.
	tests := []uint16{0, 1, 80, 443, 8080, 65535, 0x1234, 0xABCD}

	for _, p := range tests {
		p := p
		t.Run("symmetry", func(t *testing.T) {
			t.Parallel()

			if hostToNetworkPort(p) != networkToHostPort(p) {
				t.Fatalf("expected hostToNetworkPort == networkToHostPort for 0x%04X", p)
			}
		})
	}
}
