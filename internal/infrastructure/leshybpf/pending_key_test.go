package leshybpf

import (
	"encoding/hex"
	"net"
	"testing"
)

func TestPendingKeyPendingSrc_Packing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		ip       string
		port     uint16
		wantHex  string
		wantFail bool
	}{
		{
			name:    "ok_1.2.3.4_8080",
			ip:      "1.2.3.4",
			port:    8080, // 0x1F90 -> little-endian bytes 90 1f
			wantHex: "01020304901f0000",
		},
		{
			name:    "ok_127.0.0.1_1",
			ip:      "127.0.0.1",
			port:    1, // 0x0001 -> 01 00
			wantHex: "7f00000101000000",
		},
		{
			name:    "ok_10.20.30.40_65535",
			ip:      "10.20.30.40",
			port:    65535, // 0xFFFF -> ff ff
			wantHex: "0a141e28ffff0000",
		},
		{
			name:     "fail_ipv6",
			ip:       "2001:db8::1",
			port:     80,
			wantFail: true,
		},
		{
			name:     "fail_bad_ip",
			ip:       "not-an-ip",
			port:     80,
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			parsed := net.ParseIP(tt.ip)
			if parsed == nil && !tt.wantFail {
				t.Fatalf("net.ParseIP(%q) returned nil, test case is invalid", tt.ip)
			}

			key, err := pendingKeyPendingSrc(parsed, tt.port)
			if tt.wantFail {
				if err == nil {
					t.Fatalf("expected error, got nil. key=%x", key)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			gotHex := hex.EncodeToString(key[:])
			if gotHex != tt.wantHex {
				t.Fatalf("wrong key packing:\n  got : %s\n  want: %s\n  raw : %x", gotHex, tt.wantHex, key)
			}

			// Дополнительная проверка: паддинг должен быть нулевой
			if key[6] != 0 || key[7] != 0 {
				t.Fatalf("pad bytes must be zero, got pad=%02x%02x", key[6], key[7])
			}
		})
	}
}
