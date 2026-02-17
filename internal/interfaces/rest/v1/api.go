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
	allowHandler := withAuthorization(d.Management, allowAuthorizationOptions{
		Method:                         http.MethodPost,
		Operation:                      "allow",
		SettingsNotFoundStatus:         http.StatusServiceUnavailable,
		SettingsNotFoundMessage:        "Authorization is unavailable",
		AuthorizationUnavailableStatus: http.StatusServiceUnavailable,
		AuthorizationUnavailableBody:   "Authorization is unavailable",
		AuthorizationFailureBody:       "allow authorization failed",
	}, makeAllowHandler(d.Filter))
	managementBlockHandler := withAuthorization(d.Management, allowAuthorizationOptions{
		Method:                         http.MethodPost,
		Operation:                      "management_block",
		SettingsNotFoundStatus:         http.StatusConflict,
		SettingsNotFoundMessage:        "management settings are not configured",
		AuthorizationUnavailableStatus: http.StatusServiceUnavailable,
		AuthorizationUnavailableBody:   "Authorization is unavailable",
		AuthorizationFailureBody:       "management block authorization failed",
	}, makeManagementBlockHandler(d.Filter, d.Management))
	statsHandler := withAuthorization(d.Management, allowAuthorizationOptions{
		Method:                       http.MethodGet,
		Operation:                    "stats",
		SettingsNotFoundStatus:       http.StatusServiceUnavailable,
		SettingsNotFoundMessage:      "Authorization is unavailable",
		AuthorizationUnavailableBody: "Authorization is unavailable",
		AuthorizationFailureBody:     "stats authorization failed",
	}, makeStatsHandler(d.Filter))

	mux.HandleFunc("/management/settings", makeManagementSettingsHandler(d.Management))
	mux.Handle("/management/block", managementBlockHandler)
	mux.Handle("/allow", allowHandler)
	mux.Handle("/stats", statsHandler)
}

// --- handlers ---

// makeStatsHandler godoc
// @Summary Показать статистику фильтра
// @Description Возвращает статистику разрешенных и заблокированных пакетов.
// @Tags filter
// @Produce json
// @Success 200 {object} restv1.StatsResponse
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "failed to get stats"
// @Failure 503 {string} string "Authorization is unavailable"
// @Security BearerAuth
// @Router /stats [get]
// makeStatsHandler подключает обработчик ручки статистики.
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

// makeAllowHandler godoc
// @Summary Разрешить временный доступ к защищенному порту
// @Description Добавляет временную авторизацию IP+порт для доступа к защищенному порту.
// @Tags filter
// @Accept json
// @Produce json
// @Param request body restv1.AllowRequest true "Allow request"
// @Success 200 {object} restv1.AllowResponse
// @Failure 400 {string} string "Invalid JSON or validation error"
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "allow failed"
// @Failure 503 {string} string "filter is not configured"
// @Security BearerAuth
// @Router /allow [post]
// makeAllowsHandler подключает обработчик ручки разрешения подключения.
func makeAllowHandler(filterUseCase filter.UseCase) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			methodNotAllowed(w, []string{http.MethodPost})

			return
		}

		if filterUseCase == nil {
			http.Error(w, "filter usecase is not configured", http.StatusInternalServerError)

			return
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
	patchHandler := withAuthorization(managementUseCase, allowAuthorizationOptions{
		Method:                         http.MethodPatch,
		Operation:                      "management_settings_update",
		SettingsNotFoundStatus:         http.StatusConflict,
		SettingsNotFoundMessage:        "management settings are not configured",
		AuthorizationUnavailableStatus: http.StatusServiceUnavailable,
		AuthorizationUnavailableBody:   "Authorization is unavailable",
		AuthorizationFailureBody:       "management settings authorization failed",
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleManagementSettingsPatch(w, r, managementUseCase)
	}))
	getHandler := withAuthorization(managementUseCase, allowAuthorizationOptions{
		Method:                         http.MethodGet,
		Operation:                      "management_settings_show",
		SettingsNotFoundStatus:         http.StatusConflict,
		SettingsNotFoundMessage:        "management settings are not configured",
		AuthorizationUnavailableStatus: http.StatusServiceUnavailable,
		AuthorizationUnavailableBody:   "Authorization is unavailable",
		AuthorizationFailureBody:       "management settings authorization failed",
	}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleManagementSettingsGet(w, r, managementUseCase)
	}))

	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			handleManagementSettingsSave(w, r, managementUseCase)
		case http.MethodPatch:
			patchHandler.ServeHTTP(w, r)
		case http.MethodGet:
			getHandler.ServeHTTP(w, r)
		default:
			methodNotAllowed(w, []string{http.MethodGet, http.MethodPost, http.MethodPatch})
		}
	}
}

// handleManagementSettingsSave godoc
// @Summary Создать management settings (bootstrap)
// @Description Первичная конфигурация управления через bootstrap-токен.
// @Tags management
// @Accept json
// @Produce json
// @Param X-Bootstrap-Token header string true "Bootstrap token"
// @Param request body restv1.UpsertManagementSettingsRequest true "Management settings payload"
// @Success 200 {object} restv1.UpsertManagementSettingsResponse
// @Failure 400 {string} string "Invalid JSON or validation error"
// @Failure 401 {string} string "Unauthorized"
// @Failure 409 {string} string "management settings are locked"
// @Failure 500 {string} string "failed to save management settings"
// @Failure 503 {string} string "management bootstrap is not configured"
// @Security BootstrapAuth
// @Router /management/settings [post]
// handleManagementSettingsSave подключает обработчик первоначального сохранения настроек.
func handleManagementSettingsSave(
	w http.ResponseWriter,
	r *http.Request,
	managementUseCase management.UseCase,
) {
	if managementUseCase == nil {
		http.Error(w, "management settings usecase is not configured", http.StatusInternalServerError)

		return
	}
	logMutationRequestSource(r, "management_settings_create")

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
		InactiveTimerSec:   req.InactiveTimerSec,
	})
	if err != nil {
		switch {
		case errors.Is(err, management.ErrInvalidIssuer),
			errors.Is(err, management.ErrInvalidAudience),
			errors.Is(err, management.ErrInvalidJWKSURL),
			errors.Is(err, management.ErrInvalidRequiredScope),
			errors.Is(err, management.ErrInvalidGuardedPortsRange),
			errors.Is(err, management.ErrInvalidIface),
			errors.Is(err, management.ErrInvalidHandshakeWindow),
			errors.Is(err, management.ErrInvalidInactiveTimer):
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		default:
			http.Error(w, "failed to save management settings", http.StatusInternalServerError)

			return
		}
	}

	resp := managementSettingsResponse("Management settings saved", stored)
	if err := writeJSON(w, resp); err != nil {
		log.Error().Err(err).Msg("Failed to write JSON response")
	}
}

// handleManagementSettingsPatch godoc
// @Summary Обновить management settings
// @Description Обновляет уже сохраненные настройки управления.
// @Tags management
// @Accept json
// @Produce json
// @Param request body restv1.UpsertManagementSettingsRequest true "Management settings payload"
// @Success 200 {object} restv1.UpsertManagementSettingsResponse
// @Failure 400 {string} string "Invalid JSON or validation error"
// @Failure 401 {string} string "Unauthorized"
// @Failure 409 {string} string "management settings are not configured"
// @Failure 500 {string} string "failed to update management settings"
// @Failure 503 {string} string "Authorization is unavailable"
// @Security BearerAuth
// @Router /management/settings [patch]
// handleManagementSettingsPatch подключает обработчик изменения существующих настроек.
func handleManagementSettingsPatch(
	w http.ResponseWriter,
	r *http.Request,
	managementUseCase management.UseCase,
) {
	if managementUseCase == nil {
		http.Error(w, "management settings usecase is not configured", http.StatusInternalServerError)

		return
	}

	req, err := decodeManagementSettingsJSON(r)
	if err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)

		return
	}

	stored, err := managementUseCase.UpdateSettings(r.Context(), management.Settings{
		Issuer:             req.Issuer,
		Audience:           req.Audience,
		JWKSURL:            req.JWKSURL,
		RequiredScope:      req.RequiredScope,
		GuardedPortsRange:  req.GuardedPortsRange,
		Iface:              req.Iface,
		HandshakeWindowSec: req.HandshakeWindowSec,
		InactiveTimerSec:   req.InactiveTimerSec,
	})
	if err != nil {
		switch {
		case errors.Is(err, management.ErrInvalidIssuer),
			errors.Is(err, management.ErrInvalidAudience),
			errors.Is(err, management.ErrInvalidJWKSURL),
			errors.Is(err, management.ErrInvalidRequiredScope),
			errors.Is(err, management.ErrInvalidGuardedPortsRange),
			errors.Is(err, management.ErrInvalidIface),
			errors.Is(err, management.ErrInvalidHandshakeWindow),
			errors.Is(err, management.ErrInvalidInactiveTimer):
			http.Error(w, err.Error(), http.StatusBadRequest)

			return
		case errors.Is(err, management.ErrSettingsNotFound):
			http.Error(w, "management settings are not configured", http.StatusConflict)

			return
		default:
			http.Error(w, "failed to update management settings", http.StatusInternalServerError)

			return
		}
	}

	resp := managementSettingsResponse("Management settings updated", stored)
	if err := writeJSON(w, resp); err != nil {
		log.Error().Err(err).Msg("Failed to write JSON response")
	}
}

// handleManagementSettingsGet godoc
// @Summary Получить management settings
// @Description Возвращает текущие настройки управления и runtime-статус.
// @Tags management
// @Produce json
// @Success 200 {object} restv1.GetManagementSettingsResponse
// @Failure 401 {string} string "Unauthorized"
// @Failure 404 {string} string "management settings not found"
// @Failure 500 {string} string "failed to get management settings"
// @Failure 503 {string} string "Authorization is unavailable"
// @Security BearerAuth
// @Router /management/settings [get]
// handleManagementSettingsGet подключает обработчик отображения существующих настроек.
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
		InactiveTimerSec:   stored.InactiveTimerSec,
		UpdatedAt:          stored.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if err := writeJSON(w, resp); err != nil {
		log.Error().Err(err).Msg("Failed to write JSON response")
	}
}

// makeManagementBlockHandler godoc
// @Summary Экстренно заблокировать все разрешения
// @Description Очищает pending и active flow авторизации, созданные через /allow.
// @Tags management
// @Produce json
// @Success 200 {object} restv1.BlockManagementResponse
// @Failure 401 {string} string "Unauthorized"
// @Failure 500 {string} string "failed to block all connections"
// @Failure 503 {string} string "filter is not configured or authorization unavailable"
// @Security BearerAuth
// @Router /management/block [post]
// makeManagementBlockHandler подлючает обработчик блокировки всех подключений.
func makeManagementBlockHandler(
	filterUseCase filter.UseCase,
	managementUseCase management.UseCase,
) http.HandlerFunc {
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

		result, err := filterUseCase.BlockAll(r.Context())
		if err != nil {
			switch {
			case errors.Is(err, filter.ErrNotConfigured):
				http.Error(w, "filter is not configured", http.StatusServiceUnavailable)

				return
			default:
				http.Error(w, "failed to block all connections", http.StatusInternalServerError)

				return
			}
		}

		runtimeStatus := managementUseCase.RuntimeStatus(r.Context())
		resp := restv1.BlockManagementResponse{
			Message:               "All allow rules were flushed",
			PendingEntriesRemoved: result.PendingEntriesRemoved,
			ActiveFlowsRemoved:    result.ActiveFlowsRemoved,
			RuntimeAttached:       runtimeStatus.Attached,
			RuntimeIface:          runtimeStatus.Iface,
		}
		if err := writeJSON(w, resp); err != nil {
			log.Error().Err(err).Msg("Failed to write JSON response")
		}
	}
}

func managementSettingsResponse(
	message string,
	stored management.StoredSettings,
) restv1.UpsertManagementSettingsResponse {
	return restv1.UpsertManagementSettingsResponse{
		Message:            message,
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
		InactiveTimerSec:   stored.InactiveTimerSec,
		UpdatedAt:          stored.UpdatedAt.UTC().Format(time.RFC3339),
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
	if req.InactiveTimerSec == 0 {
		return req, errors.New("inactive_timer_sec is required")
	}

	// Смысловая валидация значений выполняется при записи настроек ((s *Service) SaveSettings)
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

func logMutationRequestSource(r *http.Request, operation string) {
	sourceIP := sourceIPFromRequest(r)
	log.Info().
		Str("operation", operation).
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Str("source_ip", sourceIP).
		Msg("Mutation request source recorded")
}

func logMutationAuthError(r *http.Request, operation string) {
	sourceIP := sourceIPFromRequest(r)
	log.Warn().
		Str("operation", operation).
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Str("source_ip", sourceIP).
		Msg("Mutation request auth error")
}

func sourceIPFromRequest(r *http.Request) string {
	if r == nil {
		return "unknown"
	}

	remote := strings.TrimSpace(r.RemoteAddr)
	if remote == "" {
		return "unknown"
	}

	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		if ip := net.ParseIP(remote); ip != nil {
			return ip.String()
		}

		return remote
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}

	return host
}

type allowAuthorizationOptions struct {
	Method                         string
	Operation                      string
	SettingsNotFoundStatus         int
	SettingsNotFoundMessage        string
	AuthorizationUnavailableStatus int
	AuthorizationUnavailableBody   string
	AuthorizationFailureBody       string
}

func withAuthorization(
	managementUseCase management.UseCase,
	options allowAuthorizationOptions,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if options.Method != "" && r.Method != options.Method {
			next.ServeHTTP(w, r)

			return
		}

		if managementUseCase == nil {
			http.Error(w, "management settings usecase is not configured", http.StatusInternalServerError)

			return
		}

		accessToken, err := extractBearerAccessToken(r.Header.Get("Authorization"))
		if err != nil {
			logMutationAuthError(r, options.Operation)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)

			return
		}

		if err := managementUseCase.AuthorizeAllow(r.Context(), accessToken); err != nil {
			logMutationAuthError(r, options.Operation)
			writeAllowAuthorizationError(w, options, err)

			return
		}

		logMutationRequestSource(r, options.Operation)
		next.ServeHTTP(w, r)
	})
}

func writeAllowAuthorizationError(w http.ResponseWriter, options allowAuthorizationOptions, err error) {
	switch {
	case errors.Is(err, management.ErrInvalidAccessToken):
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	case errors.Is(err, management.ErrSettingsNotFound):
		http.Error(w, settingsNotFoundMessage(options), settingsNotFoundStatus(options))
	case errors.Is(err, management.ErrAuthorizationUnavailable):
		http.Error(w, authorizationUnavailableMessage(options), authorizationUnavailableStatus(options))
	default:
		http.Error(w, authorizationFailureMessage(options), http.StatusInternalServerError)
	}
}

func settingsNotFoundStatus(options allowAuthorizationOptions) int {
	if options.SettingsNotFoundStatus != 0 {
		return options.SettingsNotFoundStatus
	}

	return http.StatusServiceUnavailable
}

func settingsNotFoundMessage(options allowAuthorizationOptions) string {
	if options.SettingsNotFoundMessage != "" {
		return options.SettingsNotFoundMessage
	}

	return "Authorization is unavailable"
}

func authorizationUnavailableStatus(options allowAuthorizationOptions) int {
	if options.AuthorizationUnavailableStatus != 0 {
		return options.AuthorizationUnavailableStatus
	}

	return http.StatusServiceUnavailable
}

func authorizationUnavailableMessage(options allowAuthorizationOptions) string {
	if options.AuthorizationUnavailableBody != "" {
		return options.AuthorizationUnavailableBody
	}

	return "Authorization is unavailable"
}

func authorizationFailureMessage(options allowAuthorizationOptions) string {
	if options.AuthorizationFailureBody != "" {
		return options.AuthorizationFailureBody
	}

	return "authorization failed"
}
