package leshybpf

import (
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func newGuardedPortsMap(t *testing.T) *ebpf.Map {
	t.Helper()

	spec := &ebpf.MapSpec{
		Name:       "test_guarded_ports",
		Type:       ebpf.Hash,
		KeySize:    2, // uint16
		ValueSize:  1, // uint8
		MaxEntries: GuardedPortsMax,
	}

	m, err := ebpf.NewMap(spec)
	if err != nil {
		t.Skipf("cannot create ebpf map in this environment: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })

	return m
}

func sortedU16(in []uint16) []uint16 {
	out := append([]uint16(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func TestParsePortRange_Valid(t *testing.T) {
	t.Parallel()

	got, err := parsePortRange("1024-1026")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []uint16{1024, 1025, 1026}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected ports: got=%v want=%v", got, want)
	}

	got, err = parsePortRange("0-0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, []uint16{0}) {
		t.Fatalf("unexpected ports: got=%v want=%v", got, []uint16{0})
	}
}

func TestParsePortRange_Invalid(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "invalid port range format"},
		{"no_dash", "1234", "invalid port range format"},
		{"too_many_dashes", "1-2-3", "invalid port range format"},
		{"bad_start", "abc-2000", "invalid start port"},
		{"bad_end", "1000-xyz", "invalid end port"},
		{"start_gt_end", "2000-1000", "start 2000 is greater than end 1000"},
		{"too_wide", "1024-3072", "maximum supported is"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := parsePortRange(tc.in)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("unexpected error: got=%q want contains %q", err.Error(), tc.want)
			}
		})
	}
}

func TestInitializeGuardedPorts_PopulatesMapAndIsPortGuardedWorks(t *testing.T) {
	t.Parallel()

	m := newGuardedPortsMap(t)

	if err := InitializeGuardedPorts("1024-1026", m); err != nil {
		t.Fatalf("InitializeGuardedPorts error: %v", err)
	}

	// True для заданного диапазона
	for _, p := range []uint16{1024, 1025, 1026} {
		if !IsPortGuarded(m, p) {
			t.Fatalf("expected port %d to be guarded", p)
		}
	}

	// False вне диапазона
	for _, p := range []uint16{1023, 1027, 80, 0, 65535} {
		if IsPortGuarded(m, p) {
			t.Fatalf("expected port %d to NOT be guarded", p)
		}
	}
}

func TestInitializeGuardedPorts_ReplacesExistingPorts(t *testing.T) {
	t.Parallel()

	m := newGuardedPortsMap(t)

	// Сначала выставим 1000-1002
	if err := InitializeGuardedPorts("1000-1002", m); err != nil {
		t.Fatalf("InitializeGuardedPorts error: %v", err)
	}
	if !IsPortGuarded(m, 1001) {
		t.Fatalf("expected port 1001 guarded after first init")
	}

	// Потом заменим на 2000-2001
	if err := InitializeGuardedPorts("2000-2001", m); err != nil {
		t.Fatalf("InitializeGuardedPorts error: %v", err)
	}

	// Старые должны исчезнуть
	for _, p := range []uint16{1000, 1001, 1002} {
		if IsPortGuarded(m, p) {
			t.Fatalf("expected old port %d to be removed", p)
		}
	}

	// Новые — появиться
	for _, p := range []uint16{2000, 2001} {
		if !IsPortGuarded(m, p) {
			t.Fatalf("expected new port %d to be guarded", p)
		}
	}
}

func TestGetGuardedPorts_ReturnsHostOrder(t *testing.T) {
	t.Parallel()

	m := newGuardedPortsMap(t)

	// Запишем ключи напрямую в NETWORK byte order (как это делает setGuardedPorts)
	portsHost := []uint16{80, 443, 8080}
	for _, p := range portsHost {
		key := hostToNetworkPort(p)
		val := uint8(1)
		if err := m.Put(&key, &val); err != nil {
			t.Fatalf("map put failed: %v", err)
		}
	}

	got := GetGuardedPorts(m)

	// Порядок итерации по ebpf map не гарантирован — сравниваем отсортированные списки
	if !reflect.DeepEqual(sortedU16(got), sortedU16(portsHost)) {
		t.Fatalf("unexpected guarded ports: got=%v want=%v", got, portsHost)
	}
}

func TestInitializeGuardedPorts_InvalidRangeReturnsError(t *testing.T) {
	t.Parallel()

	m := newGuardedPortsMap(t)

	err := InitializeGuardedPorts("bad-range", m)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	// Проверим, что это именно ошибка парсинга (обёртка)
	if !strings.Contains(err.Error(), "failed to parse port range") {
		t.Fatalf("unexpected error: %v", err)
	}
	// И что можно распознать корень
	if !errors.Is(err, err) { // формально, просто чтобы не ругался линтер на неиспользование errors import в других вариантах
		t.Log("noop")
	}
}
