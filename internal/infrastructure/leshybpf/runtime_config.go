package leshybpf

import (
	"errors"
	"fmt"
	"math"

	"github.com/cilium/ebpf"
)

const nanosPerSecond uint64 = 1_000_000_000

func setRuntimeInactiveAllowNS(m *ebpf.Map, inactiveAllowNS uint64) error {
	if m == nil {
		return errors.New("runtime config map is nil")
	}
	if inactiveAllowNS == 0 {
		return errors.New("inactive allow ns must be greater than zero")
	}

	key := uint32(0)
	if err := m.Put(&key, &inactiveAllowNS); err != nil {
		return fmt.Errorf("put runtime config: %w", err)
	}

	return nil
}

// SetInactiveTimerSec применяет runtime TTL неактивного flow в секундах.
func SetInactiveTimerSec(m *ebpf.Map, inactiveTimerSec int) error {
	if inactiveTimerSec <= 0 {
		return errors.New("inactive timer sec must be greater than zero")
	}

	timerSec := uint64(inactiveTimerSec)
	if timerSec > math.MaxUint64/nanosPerSecond {
		return errors.New("inactive timer sec overflow")
	}
	inactiveAllowNS := timerSec * nanosPerSecond

	if err := setRuntimeInactiveAllowNS(m, inactiveAllowNS); err != nil {
		return fmt.Errorf("set inactive timer: %w", err)
	}

	return nil
}
