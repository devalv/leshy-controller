package router

import (
	"net/http"
)

// Options задаёт общие REST маршруты/поведение.
type Options struct {
	// HealthPath — эндпоинт для health check.
	// Например: "/api/healthz"
	HealthPath string
}

// New создает root http.Handler для REST.
// versions: ключ — префикс версии (например "/api/v1/"), значение — mux этой версии.
// Внутри используется StripPrefix, чтобы v1 mux мог регистрировать пути как "/allow", "/stats", ...
func New(opts Options, versions map[string]http.Handler) http.Handler {
	root := http.NewServeMux()

	healthPath := opts.HealthPath
	if healthPath == "" {
		healthPath = "/api/healthz"
	}

	root.HandleFunc(healthPath, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	for prefix, h := range versions {
		if h == nil {
			continue
		}
		// Монтируем версию: запрос "/api/v1/allow" попадёт внутрь v1 mux как "/allow"
		root.Handle(prefix, http.StripPrefix(trimTrailingSlash(prefix), h))
	}

	return root
}

// trimTrailingSlash превращает "/api/v1/" -> "/api/v1" для корректного StripPrefix.
func trimTrailingSlash(prefix string) string {
	if len(prefix) > 1 && prefix[len(prefix)-1] == '/' {
		return prefix[:len(prefix)-1]
	}

	return prefix
}
