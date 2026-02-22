package leshybpf

import (
	"math"
	"testing"
	"time"
)

func TestGetUnixNanoUint64_IsNonZeroAndReasonable(t *testing.T) {
	t.Parallel()

	got := getUnixNanoUint64()
	if got == 0 {
		t.Fatalf("expected non-zero unix nano timestamp, got 0")
	}

	// Сравним с текущим временем с запасом
	now := uint64(time.Now().UnixNano())
	if got > now+uint64(2*time.Second) {
		t.Fatalf("timestamp is too far in the future: got=%d now=%d", got, now)
	}

	// И не слишком в прошлом (на случай проблем на CI/контейнере)
	if now > got+uint64(2*time.Second) {
		t.Fatalf("timestamp is too far in the past: got=%d now=%d", got, now)
	}
}

func TestGetUnixNanoUint64_IsMonotonicInPractice(t *testing.T) {
	t.Parallel()

	a := getUnixNanoUint64()
	time.Sleep(1 * time.Millisecond)
	b := getUnixNanoUint64()

	if b <= a {
		t.Fatalf("expected second timestamp to be greater: a=%d b=%d", a, b)
	}
}

func TestGetExpiryUint64_PositiveWindowIsInFuture(t *testing.T) {
	t.Parallel()

	now := getMonotonicNanoUint64()
	if now == 0 {
		t.Skip("CLOCK_MONOTONIC is unavailable in this environment")
	}
	window := 250 * time.Millisecond

	exp := getExpiryUint64(window)
	if exp == 0 {
		t.Fatalf("expected non-zero expiry for positive window")
	}

	// exp должен быть >= now (с допуском на планировщик) и примерно now+window
	if exp+uint64(20*time.Millisecond) < now {
		t.Fatalf("expiry is unexpectedly in the past: exp=%d now=%d", exp, now)
	}

	wantMin := now + uint64(window) - uint64(100*time.Millisecond)
	wantMax := now + uint64(window) + uint64(500*time.Millisecond)
	if exp < wantMin || exp > wantMax {
		t.Fatalf("expiry out of expected range: exp=%d want between [%d..%d]", exp, wantMin, wantMax)
	}
}

func TestGetExpiryUint64_ZeroWindowIsApproximatelyNow(t *testing.T) {
	t.Parallel()

	before := getMonotonicNanoUint64()
	if before == 0 {
		t.Skip("CLOCK_MONOTONIC is unavailable in this environment")
	}
	exp := getExpiryUint64(0)
	after := getMonotonicNanoUint64()
	if after == 0 {
		t.Skip("CLOCK_MONOTONIC is unavailable in this environment")
	}

	if exp == 0 {
		t.Fatalf("expected non-zero expiry for zero window")
	}

	// exp должен оказаться между before и after (или очень близко)
	// допускаем небольшой сдвиг из-за планировщика/часов
	const slack = 50 * time.Millisecond
	if exp+uint64(slack) < before || exp > after+uint64(slack) {
		t.Fatalf("expiry not close to now: exp=%d before=%d after=%d", exp, before, after)
	}
}

func TestGetExpiryUint64_NegativeHugeWindowReturnsZero(t *testing.T) {
	t.Parallel()

	// Самое большое отрицательное значение, которое точно помещается в time.Duration.
	window := -time.Duration((1 << 63) - 1) // ~= math.MaxInt64

	exp := getExpiryUint64(window)
	if exp != 0 {
		t.Fatalf("expected 0 for expiry before 1970, got=%d", exp)
	}
}

func TestDescribeMonotonicExpiry(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, time.February, 16, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		expiryMono    uint64
		nowMono       uint64
		nowWall       time.Time
		wantOK        bool
		wantRemaining time.Duration
	}{
		{
			name:          "future expiry",
			expiryMono:    2_000,
			nowMono:       1_000,
			nowWall:       base,
			wantOK:        true,
			wantRemaining: time.Microsecond,
		},
		{
			name:          "past expiry",
			expiryMono:    1_000,
			nowMono:       2_500,
			nowWall:       base,
			wantOK:        true,
			wantRemaining: -1500 * time.Nanosecond,
		},
		{
			name:          "invalid zero expiry",
			expiryMono:    0,
			nowMono:       2_500,
			nowWall:       base,
			wantOK:        false,
			wantRemaining: 0,
		},
		{
			name:          "invalid zero monotonic now",
			expiryMono:    10,
			nowMono:       0,
			nowWall:       base,
			wantOK:        false,
			wantRemaining: 0,
		},
		{
			name:          "invalid zero wall time",
			expiryMono:    10,
			nowMono:       1,
			nowWall:       time.Time{},
			wantOK:        false,
			wantRemaining: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotUTC, gotRemaining, gotOK := describeMonotonicExpiry(tt.expiryMono, tt.nowMono, tt.nowWall)
			if gotOK != tt.wantOK {
				t.Fatalf("ok = %v, want %v", gotOK, tt.wantOK)
			}

			if !tt.wantOK {
				if !gotUTC.IsZero() || gotRemaining != 0 {
					t.Fatalf("expected zero values, got utc=%v remaining=%v", gotUTC, gotRemaining)
				}

				return
			}

			if gotRemaining != tt.wantRemaining {
				t.Fatalf("remaining = %v, want %v", gotRemaining, tt.wantRemaining)
			}

			wantUTC := tt.nowWall.UTC().Add(tt.wantRemaining)
			if !gotUTC.Equal(wantUTC) {
				t.Fatalf("approx utc = %v, want %v", gotUTC, wantUTC)
			}
		})
	}
}

func TestMonotonicDeltaDurationClamp(t *testing.T) {
	t.Parallel()

	gotFuture := monotonicDeltaDuration(maxInt64AsUint64+100, 0)
	if gotFuture != time.Duration(math.MaxInt64) {
		t.Fatalf("future clamp = %v, want %v", gotFuture, time.Duration(math.MaxInt64))
	}

	gotPast := monotonicDeltaDuration(0, maxInt64AsUint64+100)
	if gotPast != -time.Duration(math.MaxInt64) {
		t.Fatalf("past clamp = %v, want %v", gotPast, -time.Duration(math.MaxInt64))
	}
}
