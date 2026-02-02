package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/devalv/leshy-controller/internal/application/filter"
	restv1 "github.com/devalv/leshy-controller/internal/contracts/rest/v1"
	"github.com/rs/zerolog/log"
)

type Deps struct {
	Filter filter.UseCase
}

func Register(mux *http.ServeMux, d Deps) { //nolint
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, []string{http.MethodGet})

			return
		}

		st, err := d.Filter.Stats(r.Context())
		if err != nil {
			http.Error(w, "failed to get stats", http.StatusInternalServerError)

			return
		}
		resp := restv1.StatsResponse{
			Allowed:                st.Allowed,
			Dropped:                st.Dropped,
			SYNAllowed:             st.SYNAllowed,
			SYNDropped:             st.SYNDropped,
			ActiveFlowHits:         st.ActiveFlowHits,
			PendingPromotions:      st.PendingPromotions,
			PendingExpiredCleanups: st.PendingExpiredCleanups,
			IPPortAuthHits:         st.IPPortAuthHits,
			NonGuardedPortAllowed:  st.NonGuardedPortAllowed,
			GuardedPortDropped:     st.GuardedPortDropped,
			AllowRatePercent:       st.AllowRatePercent,
			DropRatePercent:        st.DropRatePercent,
		}

		err = writeJSON(w, http.StatusOK, resp)
		if err != nil {
			log.Error().Err(err).Msg("Failed to write JSON response")
		}
	})

	mux.HandleFunc("/allow", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, []string{http.MethodPost})

			return
		}

		req, err := decodeJSON[restv1.AllowRequest](r)
		if err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)

			return
		}

		ip, err := extractIPv4(r, req.IP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		expires, err := d.Filter.Allow(r.Context(), ip, req.Port)
		if err != nil {
			switch {
			case errors.Is(err, filter.ErrInvalidPort):
				http.Error(w, "Valid port number required", http.StatusBadRequest)

				return
			case errors.Is(err, filter.ErrPortNotGuarded):
				http.Error(w, "Port is not guarded - no authorization needed", http.StatusBadRequest)

				return
			default:
				http.Error(w, "allow failed", http.StatusInternalServerError)

				return
			}
		}

		resp := restv1.AllowResponse{
			Message: "Access granted",
			Expires: expires.UTC().Format(time.RFC3339),
			IP:      ip.String(),
			Port:    req.Port,
		}
		err = writeJSON(w, http.StatusOK, resp)
		if err != nil {
			log.Error().Err(err).Msg("Failed to write JSON response")
		}
	})
}

// --- helpers ---

func methodNotAllowed(w http.ResponseWriter, allowed []string) {
	w.Header().Set("Allow", joinAllowed(allowed))
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func joinAllowed(methods []string) string {
	if len(methods) == 0 {
		return ""
	}
	out := methods[0]
	for i := 1; i < len(methods); i++ {
		out += ", " + methods[i] // TODO: not optimmal
	}

	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}

	return nil
}

func decodeJSON[T any](r *http.Request) (T, error) { //nolint:ireturn
	var zero T
	if r.Body == nil {
		return zero, errors.New("empty body")
	}
	defer r.Body.Close() //nolint

	var v T
	if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
		return zero, err //nolint
	}

	return v, nil
}

func extractIPv4(r *http.Request, override string) (net.IP, error) {
	var ip net.IP

	if override != "" {
		ip = net.ParseIP(override)
	} else {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip = net.ParseIP(host)
	}

	if ip == nil || ip.To4() == nil {
		return nil, errors.New("IPv4 address required")
	}

	return ip.To4(), nil
}
