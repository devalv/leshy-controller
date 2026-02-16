package leshybpf

import (
	"math"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

const maxInt64AsUint64 = uint64(math.MaxInt64)

func getUnixNanoUint64() uint64 {
	nano := time.Now().UnixNano()
	if nano < 0 {
		// В теории это невозможно, но обрабатываем для безопасности
		return 0
	}

	return uint64(nano)
}

func getMonotonicNanoUint64() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Warn().Msgf("⚠ failed to read CLOCK_MONOTONIC: %v", err)

		return 0
	}

	nano := ts.Nano()
	if nano < 0 {
		log.Warn().Msg("⚠ CLOCK_MONOTONIC returned negative value")

		return 0
	}

	return uint64(nano)
}

func getExpiryUint64(window time.Duration) uint64 {
	now := getMonotonicNanoUint64()
	if now == 0 {
		return 0
	}

	windowNano := window.Nanoseconds()
	if windowNano == 0 {
		return now
	}

	if windowNano < 0 {
		// Защита от переполнения при -math.MinInt64.
		if windowNano == math.MinInt64 {
			log.Warn().Msgf("⚠ negative window overflow: %v", window)

			return 0
		}

		delta := uint64(-windowNano)
		if delta > now {
			log.Warn().Msgf("⚠ expiry underflow for window: %v", window)

			return 0
		}

		return now - delta
	}

	delta := uint64(windowNano)
	if math.MaxUint64-now < delta {
		log.Warn().Msgf("⚠ expiry overflow for window: %v", window)

		return math.MaxUint64
	}

	// Важно: expiry хранится в шкале CLOCK_MONOTONIC, чтобы корректно сравниваться
	// в eBPF с bpf_ktime_get_ns().
	expiryNano := now + delta
	if expiryNano == 0 {
		return 0
	}

	return expiryNano
}

func describeMonotonicExpiry(expiryMono uint64, nowMono uint64, nowWall time.Time) (time.Time, time.Duration, bool) {
	if expiryMono == 0 || nowMono == 0 || nowWall.IsZero() {
		return time.Time{}, 0, false
	}

	delta := monotonicDeltaDuration(expiryMono, nowMono)

	return nowWall.UTC().Add(delta), delta, true
}

func describeMonotonicExpiryNow(expiryMono uint64) (time.Time, time.Duration, bool) {
	nowMono := getMonotonicNanoUint64()
	if nowMono == 0 {
		return time.Time{}, 0, false
	}

	return describeMonotonicExpiry(expiryMono, nowMono, time.Now().UTC())
}

func monotonicDeltaDuration(expiryMono uint64, nowMono uint64) time.Duration {
	if expiryMono >= nowMono {
		diff := expiryMono - nowMono
		if diff > maxInt64AsUint64 {
			return time.Duration(math.MaxInt64)
		}

		return time.Duration(int64(diff))
	}

	diff := nowMono - expiryMono
	if diff > maxInt64AsUint64 {
		return -time.Duration(math.MaxInt64)
	}

	return -time.Duration(int64(diff))
}
