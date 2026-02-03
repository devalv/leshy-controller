package leshybpf

import (
	"math"
	"time"

	"github.com/rs/zerolog/log"
)

func getUnixNanoUint64() uint64 {
	nano := time.Now().UnixNano()
	if nano < 0 {
		// В теории это невозможно, но обрабатываем для безопасности
		return 0
	}

	return uint64(nano)
}

func formatNanoTimestamp(value uint64) string {
	// Проверяем, что значение не слишком большое
	if value > math.MaxInt64 {
		// Если это timestamp в наносекундах, максимальное значение
		// соответствует примерно 292 годам (MaxInt64 наносекунд)
		return "⚠ Time conversion failed!"
	}

	// Безопасное преобразование
	t := time.Unix(0, int64(value)).UTC()

	return t.Format(time.RFC3339)
}

func getExpiryUint64(window time.Duration) uint64 {
	expiryNano := time.Now().Add(window).UnixNano()

	// Для expiry (времени истечения) мы обычно ожидаем будущее время
	// Если window отрицательное и приводит нас до 1970, это ошибка логики
	if expiryNano < 0 {
		log.Warn().Msgf("⚠ expiry time is before 1970. Check window: %v", window)

		return 0
	}

	return uint64(expiryNano)
}
