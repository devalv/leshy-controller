package leshybpf

import (
	"math"
	"strings"
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

func TestFormatNanoTimestamp_ZeroIsEpochUTC(t *testing.T) {
	t.Parallel()

	got := formatNanoTimestamp(0)
	want := "1970-01-01T00:00:00Z"
	if got != want {
		t.Fatalf("unexpected formatted timestamp: got=%q want=%q", got, want)
	}
}

func TestFormatNanoTimestamp_MaxInt64IsOk(t *testing.T) {
	t.Parallel()

	// MaxInt64 наносекунд от эпохи — допустимо
	got := formatNanoTimestamp(uint64(math.MaxInt64))
	if got == "" || got == "⚠ Time conversion failed!" {
		t.Fatalf("expected valid RFC3339 string, got=%q", got)
	}

	// Должно быть UTC и RFC3339 (заканчиваться на Z)
	if got[len(got)-1] != 'Z' {
		t.Fatalf("expected UTC (Z suffix), got=%q", got)
	}
}

func TestFormatNanoTimestamp_TooLargeReturnsFailureMarker(t *testing.T) {
	t.Parallel()

	got := formatNanoTimestamp(uint64(math.MaxInt64) + 1)
	want := "⚠ Time conversion failed!"
	if got != want {
		t.Fatalf("unexpected result: got=%q want=%q", got, want)
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

func TestExpiryThenFormat_IsRFC3339UTC_NotFailureMarker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		window time.Duration
	}{
		{"small_positive", 1 * time.Second},
		{"small_negative_but_not_pre1970", -1 * time.Second},
		{"zero", 0},
		{"larger_positive", 5 * time.Second},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			exp := getExpiryUint64(tt.window)
			if exp == 0 && tt.window < 0 {
				// В случае сильно отрицательных окон мы возвращаем 0.
				// Для -1s это не должно случиться, но оставим защёлку на случай нестандартного времени системы.
				t.Skipf("expiry is 0 for window=%v; system time may be unexpected", tt.window)
			}
			if exp == 0 && tt.window >= 0 {
				t.Fatalf("expected non-zero expiry for window=%v", tt.window)
			}

			s := formatNanoTimestamp(exp)

			// Для нормальных значений не должен возвращаться маркер ошибки.
			if s == "⚠ Time conversion failed!" {
				t.Fatalf("unexpected failure marker for expiry=%d window=%v", exp, tt.window)
			}

			// Должно быть UTC (RFC3339 с 'Z' в конце).
			if !strings.HasSuffix(s, "Z") {
				t.Fatalf("expected UTC (Z suffix), got %q", s)
			}

			// Строка должна парситься как RFC3339.
			parsed, err := time.Parse(time.RFC3339, s)
			if err != nil {
				t.Fatalf("expected RFC3339, parse error: %v (value=%q)", err, s)
			}

			// И она должна соответствовать исходному значению в наносекундах.
			// (UTC() в formatNanoTimestamp гарантирует единый формат)
			want := truncateToSecondNano(exp)
			if got := uint64(parsed.UTC().UnixNano()); got != want {
				t.Fatalf("roundtrip mismatch: parsed=%d want=%d (s=%q)", got, want, s)
			}
		})
	}
}

func truncateToSecondNano(n uint64) uint64 {
	const sec = uint64(1_000_000_000)
	return (n / sec) * sec
}

func TestFormatNanoTimestamp_RoundtripArbitraryValues(t *testing.T) {
	t.Parallel()

	values := []uint64{
		0,
		1,
		999,
		1_000_000_000,
		1770235561740224942, // пример
	}

	for _, v := range values {
		v := v
		t.Run("v", func(t *testing.T) {
			t.Parallel()

			s := formatNanoTimestamp(v)
			if s == "⚠ Time conversion failed!" {
				t.Fatalf("unexpected failure marker for v=%d", v)
			}

			tt, err := time.Parse(time.RFC3339, s)
			if err != nil {
				t.Fatalf("parse failed: %v (s=%q)", err, s)
			}

			got := uint64(tt.UnixNano())
			want := truncateToSecondNano(v)

			if got != want {
				t.Fatalf("roundtrip mismatch (seconds precision): parsed=%d want=%d (s=%q)", got, want, s)
			}
		})
	}
}
