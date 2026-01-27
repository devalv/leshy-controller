package v1

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/cilium/ebpf"
	"github.com/devalv/leshy-controller/internal/domain"
	"github.com/devalv/leshy-controller/internal/infrastructure"
	"github.com/rs/zerolog/log"
)

// SetupHTTPHandlers настраивает HTTP обработчики.
func SetupHTTPHandlers(window time.Duration, pendingMap, guardedPortsMap, statsMap *ebpf.Map) *http.ServeMux { //nolint
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Stats endpoint для проверки статистики BPF программы
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		stats := infrastructure.GetBPFStats(statsMap)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats) //nolint
	})

	// Main allow endpoint (без аутентификации)
	mux.HandleFunc("/allow", func(w http.ResponseWriter, r *http.Request) {
		// Parse request body
		var req domain.AllowRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)

			return
		}

		// Extract client remote IP or use provided IP
		var ip net.IP
		if req.IP != "" {
			// Use IP from request body
			ip = net.ParseIP(req.IP)
		} else {
			// Use client remote IP
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				http.Error(w, "bad remote addr: "+err.Error(), http.StatusBadRequest)

				return
			}
			ip = net.ParseIP(host)
		}

		if ip == nil || ip.To4() == nil {
			http.Error(w, "IPv4 address required", http.StatusBadRequest)

			return
		}

		if req.Port == 0 {
			http.Error(w, "Valid port number required", http.StatusBadRequest)

			return
		}

		// Check if port is guarded
		if !infrastructure.IsPortGuarded(guardedPortsMap, req.Port) {
			http.Error(w, "Port is not guarded - no authorization needed", http.StatusBadRequest)

			return
		}

		expiry := time.Now().Add(window)

		log.Info().Msgf("allowing access for %s to port %d for %s (until %s)", ip, req.Port, window, expiry.Format(time.RFC3339)) //nolint:lll

		// Insert into BPF map (with cleanup of old entry)
		if err := infrastructure.InsertPendingSrcPort(pendingMap, ip, req.Port, window); err != nil {
			log.Error().Err(err).Msg("error inserting into BPF map")
			http.Error(w, "map update failed", http.StatusInternalServerError)

			return
		}

		log.Info().Msgf("added %s:%d to pending map with %s window", ip, req.Port, window)

		// Проверяем, что запись действительно добавлена и доступна для чтения
		portNetwork := infrastructure.HostToNetworkPort(req.Port)
		keyBytes := make([]byte, 8) //nolint:mnd
		binary.BigEndian.PutUint32(keyBytes[0:4], binary.BigEndian.Uint32(ip.To4()))
		binary.BigEndian.PutUint16(keyBytes[4:6], portNetwork)
		binary.BigEndian.PutUint16(keyBytes[6:8], 0)

		var value uint64
		if err := pendingMap.Lookup(keyBytes, &value); err != nil {
			log.Warn().Err(err).Msg("  ⚠ failed to read back inserted entry")
		} else {
			log.Info().Msgf("  ✓ verified: entry exists in map, expires at %s UTC", time.Unix(0, int64(value)).UTC().Format(time.RFC3339)) //nolint
		}

		w.Header().Set("Content-Type", "application/json")
		response := domain.AllowResponse{
			Message: "Access granted",
			Expires: expiry.UTC().Format(time.RFC3339),
			IP:      ip.String(),
			Port:    req.Port,
		}
		_ = json.NewEncoder(w).Encode(response)
	})

	return mux
}
