package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/devalv/leshy-controller/internal/application/filter"
	"github.com/devalv/leshy-controller/internal/application/management"
	restv1 "github.com/devalv/leshy-controller/internal/contracts/rest/v1"
	"github.com/rs/zerolog/log"
)

type Deps struct {
	Filter     filter.UseCase
	Management management.UseCase
}

const settingsBootstrapHeader = "X-Bootstrap-Token"

func Register(mux *http.ServeMux, d Deps) {
	mux.HandleFunc("/stats", makeStatsHandler(d.Filter))
	mux.HandleFunc("/allow", makeAllowHandler(d.Filter, d.Management))
	mux.HandleFunc("/management/settings", makeManagementSettingsHandler(d.Management))
}

// --- handlers ---

func makeStatsHandler(filterUseCase filter.UseCase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			methodNotAllowed(w, []string{http.MethodGet})

			return
		}

		if filterUseCase == nil {
			http.Error(w, "filter usecase is not configured", http.StatusInternalServerError)

			return
		}

		st, err := filterUseCase.Stats(r.Context())
		if err != nil {
			if errors.Is(err, filter.ErrNotConfigured) {
				http.Error(w, "filter is not configured", http.StatusServiceUnavailable)

				return
			}

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

		if err := writeJSON(w, resp); err != nil {
			log.Error().Err(err).Msg("Failed to write JSON response")
		}
	}
}

func makeAllowHandler(filterUseCase filter.UseCase, managementUseCase management.UseCase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, []string{http.MethodPost})

			return
		}

		if filterUseCase == nil {
			http.Error(w, "filter usecase is not configured", http.StatusInternalServerError)

			return
		}
		if managementUseCase == nil {
			http.Error(w, "management settings usecase is not configured", http.StatusInternalServerError)

			return
		}

		accessToken, err := extractBearerAccessToken(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)

			return
		}
		if err := managementUseCase.AuthorizeAllow(r.Context(), accessToken); err != nil {
			switch {
			case errors.Is(err, management.ErrInvalidAccessToken):
				http.Error(w, "Unauthorized", http.StatusUnauthorized)

				return
			case errors.Is(err, management.ErrSettingsNotFound),
				errors.Is(err, management.ErrAuthorizationUnavailable):
				http.Error(w, "Authorization is unavailable", http.StatusServiceUnavailable)

				return
			default:
				http.Error(w, "allow authorization failed", http.StatusInternalServerError)

				return
			}
		}

		req, err := decodeJSON(r)
		if err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)

			return
		}

		ip, err := extractIPv4(r, req.IP)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		}

		expires, err := filterUseCase.Allow(r.Context(), ip, req.Port)
		if err != nil {
			switch {
			case errors.Is(err, filter.ErrNotConfigured):
				http.Error(w, "filter is not configured", http.StatusServiceUnavailable)

				return
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
		if err := writeJSON(w, resp); err != nil {
			log.Error().Err(err).Msg("Failed to write JSON response")
		}
	}
}

func makeManagementSettingsHandler(managementUseCase management.UseCase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handleManagementSettingsSave(w, r, managementUseCase)
		case http.MethodGet:
			handleManagementSettingsGet(w, r, managementUseCase)
		default:
			methodNotAllowed(w, []string{http.MethodGet, http.MethodPost})
		}
	}
}

func handleManagementSettingsSave(
	w http.ResponseWriter,
	r *http.Request,
	managementUseCase management.UseCase,
) {
	if managementUseCase == nil {
		http.Error(w, "management settings usecase is not configured", http.StatusInternalServerError)

		return
	}

	bootstrapToken := r.Header.Get(settingsBootstrapHeader)
	if err := managementUseCase.AuthorizeSettingsBootstrap(r.Context(), bootstrapToken); err != nil {
		switch {
		case errors.Is(err, management.ErrInvalidBootstrapToken):
			http.Error(w, "Unauthorized", http.StatusUnauthorized)

			return
		case errors.Is(err, management.ErrBootstrapLocked):
			http.Error(w, "management settings are locked", http.StatusConflict)

			return
		case errors.Is(err, management.ErrBootstrapNotConfigured):
			http.Error(w, "management bootstrap is not configured", http.StatusServiceUnavailable)

			return
		default:
			http.Error(w, "failed to authorize management settings update", http.StatusInternalServerError)

			return
		}
	}

	req, err := decodeManagementSettingsJSON(r)
	if err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)

		return
	}

	stored, err := managementUseCase.SaveSettings(r.Context(), management.Settings{
		Issuer:             req.Issuer,
		Audience:           req.Audience,
		JWKSURL:            req.JWKSURL,
		RequiredScope:      req.RequiredScope,
		GuardedPortsRange:  req.GuardedPortsRange,
		Iface:              req.Iface,
		HandshakeWindowSec: req.HandshakeWindowSec,
	})
	if err != nil {
		switch {
		case errors.Is(err, management.ErrInvalidIssuer),
			errors.Is(err, management.ErrInvalidAudience),
			errors.Is(err, management.ErrInvalidJWKSURL),
			errors.Is(err, management.ErrInvalidRequiredScope),
			errors.Is(err, management.ErrInvalidGuardedPortsRange),
			errors.Is(err, management.ErrInvalidIface),
			errors.Is(err, management.ErrInvalidHandshakeWindow):
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		default:
			http.Error(w, "failed to save management settings", http.StatusInternalServerError)

			return
		}
	}

	resp := restv1.UpsertManagementSettingsResponse{
		Message:            "Management settings saved",
		AuthConfigured:     stored.Issuer != "" && stored.JWKSURL != "",
		RuntimeAttached:    stored.Runtime.Attached,
		RuntimeIface:       stored.Runtime.Iface,
		Issuer:             stored.Issuer,
		Audience:           stored.Audience,
		JWKSURL:            stored.JWKSURL,
		RequiredScope:      stored.RequiredScope,
		GuardedPortsRange:  stored.GuardedPortsRange,
		Iface:              stored.Iface,
		HandshakeWindowSec: stored.HandshakeWindowSec,
		UpdatedAt:          stored.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if err := writeJSON(w, resp); err != nil {
		log.Error().Err(err).Msg("Failed to write JSON response")
	}
}

func handleManagementSettingsGet(
	w http.ResponseWriter,
	r *http.Request,
	managementUseCase management.UseCase,
) {
	if managementUseCase == nil {
		http.Error(w, "management settings usecase is not configured", http.StatusInternalServerError)

		return
	}

	stored, err := managementUseCase.GetSettings(r.Context())
	if err != nil {
		if errors.Is(err, management.ErrSettingsNotFound) {
			http.Error(w, "management settings not found", http.StatusNotFound)

			return
		}

		http.Error(w, "failed to get management settings", http.StatusInternalServerError)

		return
	}

	resp := restv1.GetManagementSettingsResponse{
		AuthConfigured:     stored.Issuer != "" && stored.JWKSURL != "",
		RuntimeAttached:    stored.Runtime.Attached,
		RuntimeIface:       stored.Runtime.Iface,
		Issuer:             stored.Issuer,
		Audience:           stored.Audience,
		JWKSURL:            stored.JWKSURL,
		RequiredScope:      stored.RequiredScope,
		GuardedPortsRange:  stored.GuardedPortsRange,
		Iface:              stored.Iface,
		HandshakeWindowSec: stored.HandshakeWindowSec,
		UpdatedAt:          stored.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if err := writeJSON(w, resp); err != nil {
		log.Error().Err(err).Msg("Failed to write JSON response")
	}
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

	out := strings.Join(methods, ", ")

	return out
}

func writeJSON(w http.ResponseWriter, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}

	return nil
}

func decodeJSON(r *http.Request) (restv1.AllowRequest, error) {
	var req restv1.AllowRequest
	if r.Body == nil {
		return req, errors.New("empty body")
	}
	defer func() {
		if closeErr := r.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("error closing request body")
		}
	}()

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, fmt.Errorf("error with JSON decoding: %w", err)
	}

	// Валидация
	if req.IP == "" {
		return req, errors.New("ip is required")
	}
	if req.Port == 0 {
		return req, errors.New("port is required")
	}

	return req, nil
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

func decodeManagementSettingsJSON(r *http.Request) (restv1.UpsertManagementSettingsRequest, error) {
	var req restv1.UpsertManagementSettingsRequest
	if r.Body == nil {
		return req, errors.New("empty body")
	}
	defer func() {
		if closeErr := r.Body.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("error closing request body")
		}
	}()

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return req, fmt.Errorf("error with JSON decoding: %w", err)
	}

	if strings.TrimSpace(req.Issuer) == "" {
		return req, errors.New("issuer is required")
	}
	if strings.TrimSpace(req.Audience) == "" {
		return req, errors.New("audience is required")
	}
	if strings.TrimSpace(req.JWKSURL) == "" {
		return req, errors.New("jwks_url is required")
	}
	if strings.TrimSpace(req.RequiredScope) == "" {
		return req, errors.New("required_scope is required")
	}
	if req.GuardedPortsRange == "" {
		return req, errors.New("guarded_ports_range is required")
	}
	if req.Iface == "" {
		return req, errors.New("iface is required")
	}
	if req.HandshakeWindowSec == 0 {
		return req, errors.New("handshake_window_sec is required")
	}

	// TODO: extra validation for incoming Settings
	return req, nil
}

func extractBearerAccessToken(headerValue string) (string, error) {
	header := strings.TrimSpace(headerValue)
	if header == "" {
		return "", errors.New("authorization header is required")
	}

	const authParts = 2
	parts := strings.SplitN(header, " ", authParts)
	if len(parts) != authParts {
		return "", errors.New("authorization header format must be Bearer <token>")
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("authorization header scheme must be Bearer")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", errors.New("bearer token is empty")
	}

	return token, nil
}
