package v1

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/devalv/leshy-controller/internal/application/filter"
	"github.com/devalv/leshy-controller/internal/application/management"
	grpcv1 "github.com/devalv/leshy-controller/internal/contracts/grpc/v1"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	authorizationMetadataKey   = "authorization"
	bootstrapMetadataKey       = "x-bootstrap-token"
	messageUnauthorized        = "Unauthorized"
	messageAuthUnavailable     = "Authorization is unavailable"
	defaultAuthFailureResponse = "authorization failed"
)

type Deps struct {
	Filter     filter.UseCase
	Management management.UseCase
}

type API struct {
	grpcv1.UnimplementedHealthServiceServer
	grpcv1.UnimplementedFilterServiceServer
	grpcv1.UnimplementedManagementServiceServer

	filter     filter.UseCase
	management management.UseCase
}

// Register регистрирует реализации gRPC контрактов v1.
func Register(registrar grpc.ServiceRegistrar, deps Deps) {
	api := New(deps)
	grpcv1.RegisterHealthServiceServer(registrar, api)
	grpcv1.RegisterFilterServiceServer(registrar, api)
	grpcv1.RegisterManagementServiceServer(registrar, api)
}

// New создает gRPC API поверх use-case слоев.
func New(deps Deps) *API {
	return &API{
		filter:     deps.Filter,
		management: deps.Management,
	}
}

func (a *API) Health(ctx context.Context, _ *emptypb.Empty) (*grpcv1.HealthResponse, error) {
	runtimeStatus := management.RuntimeStatus{}
	if a.management != nil {
		runtimeStatus = a.management.RuntimeStatus(ctx)
	}

	return &grpcv1.HealthResponse{
		Status:          "ok",
		RuntimeAttached: runtimeStatus.Attached,
	}, nil
}

func (a *API) Allow(ctx context.Context, req *grpcv1.AllowRequest) (*grpcv1.AllowResponse, error) {
	if a.filter == nil {
		return nil, grpcStatusError(codes.Internal, "filter usecase is not configured")
	}

	if err := a.authorizeBearer(ctx, authorizationOptions{
		Operation:                    "allow",
		FullMethod:                   grpcv1.FilterService_Allow_FullMethodName,
		SettingsNotFoundCode:         codes.Unavailable,
		SettingsNotFoundMessage:      messageAuthUnavailable,
		AuthorizationUnavailableCode: codes.Unavailable,
		AuthorizationUnavailableBody: messageAuthUnavailable,
		AuthorizationFailureBody:     "allow authorization failed",
	}); err != nil {
		return nil, err
	}

	if req == nil {
		return nil, grpcStatusError(codes.InvalidArgument, "request is required")
	}

	port, err := toUint16Port(req.GetPort())
	if err != nil {
		return nil, grpcStatusError(codes.InvalidArgument, "Valid port number required")
	}

	ip, err := extractIPv4(ctx, req.GetIp())
	if err != nil {
		return nil, grpcStatusError(codes.InvalidArgument, err.Error())
	}

	expires, err := a.filter.Allow(ctx, ip, port)
	if err != nil {
		switch {
		case errors.Is(err, filter.ErrNotConfigured):
			return nil, grpcStatusError(codes.Unavailable, "filter is not configured")
		case errors.Is(err, filter.ErrInvalidPort):
			return nil, grpcStatusError(codes.InvalidArgument, "Valid port number required")
		case errors.Is(err, filter.ErrPortNotGuarded):
			return nil, grpcStatusError(codes.InvalidArgument, "Port is not guarded - no authorization needed")
		default:
			return nil, grpcStatusError(codes.Internal, "allow failed")
		}
	}

	return &grpcv1.AllowResponse{
		Message:   "Access granted",
		ExpiresAt: timestamppb.New(expires.UTC()),
		Ip:        ip.String(),
		Port:      req.GetPort(),
	}, nil
}

func (a *API) Stats(ctx context.Context, _ *emptypb.Empty) (*grpcv1.StatsResponse, error) {
	if a.filter == nil {
		return nil, grpcStatusError(codes.Internal, "filter usecase is not configured")
	}

	if err := a.authorizeBearer(ctx, authorizationOptions{
		Operation:                "stats",
		FullMethod:               grpcv1.FilterService_Stats_FullMethodName,
		SettingsNotFoundCode:     codes.Unavailable,
		SettingsNotFoundMessage:  messageAuthUnavailable,
		AuthorizationFailureBody: "stats authorization failed",
	}); err != nil {
		return nil, err
	}

	st, err := a.filter.Stats(ctx)
	if err != nil {
		if errors.Is(err, filter.ErrNotConfigured) {
			return nil, grpcStatusError(codes.Unavailable, "filter is not configured")
		}

		return nil, grpcStatusError(codes.Internal, "failed to get stats")
	}

	return &grpcv1.StatsResponse{
		Allowed:                st.Allowed,
		Dropped:                st.Dropped,
		SynAllowed:             st.SYNAllowed,
		SynDropped:             st.SYNDropped,
		ActiveFlowHits:         st.ActiveFlowHits,
		PendingPromotions:      st.PendingPromotions,
		PendingExpiredCleanups: st.PendingExpiredCleanups,
		IpPortAuthHits:         st.IPPortAuthHits,
		NonGuardedPortAllowed:  st.NonGuardedPortAllowed,
		GuardedPortDropped:     st.GuardedPortDropped,
		AllowRatePercent:       st.AllowRatePercent,
		DropRatePercent:        st.DropRatePercent,
	}, nil
}

func (a *API) CreateSettings(
	ctx context.Context,
	req *grpcv1.UpsertManagementSettingsRequest,
) (*grpcv1.UpsertManagementSettingsResponse, error) {
	if a.management == nil {
		return nil, grpcStatusError(codes.Internal, "management settings usecase is not configured")
	}

	logMutationRequestSource(ctx, "management_settings_create", grpcv1.ManagementService_CreateSettings_FullMethodName)

	bootstrapToken := metadataValue(ctx, bootstrapMetadataKey)
	if err := a.management.AuthorizeSettingsBootstrap(ctx, bootstrapToken); err != nil {
		switch {
		case errors.Is(err, management.ErrInvalidBootstrapToken):
			return nil, grpcStatusError(codes.Unauthenticated, messageUnauthorized)
		case errors.Is(err, management.ErrBootstrapLocked):
			return nil, grpcStatusError(codes.FailedPrecondition, "management settings are locked")
		case errors.Is(err, management.ErrBootstrapNotConfigured):
			return nil, grpcStatusError(codes.Unavailable, "management bootstrap is not configured")
		default:
			return nil, grpcStatusError(codes.Internal, "failed to authorize management settings update")
		}
	}

	settings, err := decodeAndValidateSettings(req)
	if err != nil {
		return nil, grpcStatusError(codes.InvalidArgument, err.Error())
	}

	stored, err := a.management.SaveSettings(ctx, settings)
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
			return nil, grpcStatusError(codes.InvalidArgument, err.Error())
		default:
			return nil, grpcStatusError(codes.Internal, "failed to save management settings")
		}
	}

	response, err := upsertResponse("Management settings saved", stored)
	if err != nil {
		return nil, grpcStatusError(codes.Internal, "failed to encode management settings response")
	}

	return response, nil
}

func (a *API) UpdateSettings(
	ctx context.Context,
	req *grpcv1.UpsertManagementSettingsRequest,
) (*grpcv1.UpsertManagementSettingsResponse, error) {
	if a.management == nil {
		return nil, grpcStatusError(codes.Internal, "management settings usecase is not configured")
	}

	if err := a.authorizeBearer(ctx, authorizationOptions{
		Operation:                    "management_settings_update",
		FullMethod:                   grpcv1.ManagementService_UpdateSettings_FullMethodName,
		SettingsNotFoundCode:         codes.FailedPrecondition,
		SettingsNotFoundMessage:      "management settings are not configured",
		AuthorizationUnavailableCode: codes.Unavailable,
		AuthorizationUnavailableBody: messageAuthUnavailable,
		AuthorizationFailureBody:     "management settings authorization failed",
	}); err != nil {
		return nil, err
	}

	settings, err := decodeAndValidateSettings(req)
	if err != nil {
		return nil, grpcStatusError(codes.InvalidArgument, err.Error())
	}

	stored, err := a.management.UpdateSettings(ctx, settings)
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
			return nil, grpcStatusError(codes.InvalidArgument, err.Error())
		case errors.Is(err, management.ErrSettingsNotFound):
			return nil, grpcStatusError(codes.FailedPrecondition, "management settings are not configured")
		default:
			return nil, grpcStatusError(codes.Internal, "failed to update management settings")
		}
	}

	response, err := upsertResponse("Management settings updated", stored)
	if err != nil {
		return nil, grpcStatusError(codes.Internal, "failed to encode management settings response")
	}

	return response, nil
}

func (a *API) GetSettings(
	ctx context.Context,
	_ *emptypb.Empty,
) (*grpcv1.GetManagementSettingsResponse, error) {
	if a.management == nil {
		return nil, grpcStatusError(codes.Internal, "management settings usecase is not configured")
	}

	if err := a.authorizeBearer(ctx, authorizationOptions{
		Operation:                    "management_settings_show",
		FullMethod:                   grpcv1.ManagementService_GetSettings_FullMethodName,
		SettingsNotFoundCode:         codes.FailedPrecondition,
		SettingsNotFoundMessage:      "management settings are not configured",
		AuthorizationUnavailableCode: codes.Unavailable,
		AuthorizationUnavailableBody: messageAuthUnavailable,
		AuthorizationFailureBody:     "management settings authorization failed",
	}); err != nil {
		return nil, err
	}

	stored, err := a.management.GetSettings(ctx)
	if err != nil {
		if errors.Is(err, management.ErrSettingsNotFound) {
			return nil, grpcStatusError(codes.NotFound, "management settings not found")
		}

		return nil, grpcStatusError(codes.Internal, "failed to get management settings")
	}

	handshakeWindowSec, err := toInt32(stored.HandshakeWindowSec)
	if err != nil {
		return nil, grpcStatusError(codes.Internal, "failed to encode handshake_window_sec")
	}
	inactiveTimerSec, err := toInt32(stored.InactiveTimerSec)
	if err != nil {
		return nil, grpcStatusError(codes.Internal, "failed to encode inactive_timer_sec")
	}

	return &grpcv1.GetManagementSettingsResponse{
		AuthConfigured:     stored.Issuer != "" && stored.JWKSURL != "",
		RuntimeAttached:    stored.Runtime.Attached,
		RuntimeIface:       stored.Runtime.Iface,
		Issuer:             stored.Issuer,
		Audience:           stored.Audience,
		JwksUrl:            stored.JWKSURL,
		RequiredScope:      stored.RequiredScope,
		GuardedPortsRange:  stored.GuardedPortsRange,
		Iface:              stored.Iface,
		HandshakeWindowSec: handshakeWindowSec,
		InactiveTimerSec:   inactiveTimerSec,
		UpdatedAt:          timestamppb.New(stored.UpdatedAt.UTC()),
	}, nil
}

func (a *API) Block(ctx context.Context, _ *emptypb.Empty) (*grpcv1.BlockManagementResponse, error) {
	if a.filter == nil {
		return nil, grpcStatusError(codes.Internal, "filter usecase is not configured")
	}
	if a.management == nil {
		return nil, grpcStatusError(codes.Internal, "management settings usecase is not configured")
	}

	if err := a.authorizeBearer(ctx, authorizationOptions{
		Operation:                    "management_block",
		FullMethod:                   grpcv1.ManagementService_Block_FullMethodName,
		SettingsNotFoundCode:         codes.FailedPrecondition,
		SettingsNotFoundMessage:      "management settings are not configured",
		AuthorizationUnavailableCode: codes.Unavailable,
		AuthorizationUnavailableBody: messageAuthUnavailable,
		AuthorizationFailureBody:     "management block authorization failed",
	}); err != nil {
		return nil, err
	}

	result, err := a.filter.BlockAll(ctx)
	if err != nil {
		if errors.Is(err, filter.ErrNotConfigured) {
			return nil, grpcStatusError(codes.Unavailable, "filter is not configured")
		}

		return nil, grpcStatusError(codes.Internal, "failed to block all connections")
	}

	runtimeStatus := a.management.RuntimeStatus(ctx)

	return &grpcv1.BlockManagementResponse{
		Message:               "All allow rules were flushed",
		PendingEntriesRemoved: result.PendingEntriesRemoved,
		ActiveFlowsRemoved:    result.ActiveFlowsRemoved,
		RuntimeAttached:       runtimeStatus.Attached,
		RuntimeIface:          runtimeStatus.Iface,
	}, nil
}

type authorizationOptions struct {
	Operation                    string
	FullMethod                   string
	SettingsNotFoundCode         codes.Code
	SettingsNotFoundMessage      string
	AuthorizationUnavailableCode codes.Code
	AuthorizationUnavailableBody string
	AuthorizationFailureBody     string
}

func (a *API) authorizeBearer(ctx context.Context, options authorizationOptions) error {
	if a.management == nil {
		return grpcStatusError(codes.Internal, "management settings usecase is not configured")
	}

	accessToken, err := extractBearerAccessToken(metadataValue(ctx, authorizationMetadataKey))
	if err != nil {
		logMutationAuthError(ctx, options.Operation, options.FullMethod)

		return grpcStatusError(codes.Unauthenticated, messageUnauthorized)
	}

	if err := a.management.AuthorizeAllow(ctx, accessToken); err != nil {
		logMutationAuthError(ctx, options.Operation, options.FullMethod)

		return mapAuthorizationError(options, err)
	}

	logMutationRequestSource(ctx, options.Operation, options.FullMethod)

	return nil
}

func mapAuthorizationError(options authorizationOptions, err error) error {
	switch {
	case errors.Is(err, management.ErrInvalidAccessToken):
		return grpcStatusError(codes.Unauthenticated, messageUnauthorized)
	case errors.Is(err, management.ErrSettingsNotFound):
		return grpcStatusError(settingsNotFoundCode(options), settingsNotFoundMessage(options))
	case errors.Is(err, management.ErrAuthorizationUnavailable):
		return grpcStatusError(authorizationUnavailableCode(options), authorizationUnavailableMessage(options))
	default:
		return grpcStatusError(codes.Internal, authorizationFailureMessage(options))
	}
}

func decodeAndValidateSettings(req *grpcv1.UpsertManagementSettingsRequest) (management.Settings, error) {
	if req == nil {
		return management.Settings{}, errors.New("request is required")
	}
	if strings.TrimSpace(req.GetIssuer()) == "" {
		return management.Settings{}, errors.New("issuer is required")
	}
	if strings.TrimSpace(req.GetAudience()) == "" {
		return management.Settings{}, errors.New("audience is required")
	}
	if strings.TrimSpace(req.GetJwksUrl()) == "" {
		return management.Settings{}, errors.New("jwks_url is required")
	}
	if strings.TrimSpace(req.GetRequiredScope()) == "" {
		return management.Settings{}, errors.New("required_scope is required")
	}
	if strings.TrimSpace(req.GetGuardedPortsRange()) == "" {
		return management.Settings{}, errors.New("guarded_ports_range is required")
	}
	if strings.TrimSpace(req.GetIface()) == "" {
		return management.Settings{}, errors.New("iface is required")
	}
	if req.GetHandshakeWindowSec() == 0 {
		return management.Settings{}, errors.New("handshake_window_sec is required")
	}
	if req.GetInactiveTimerSec() == 0 {
		return management.Settings{}, errors.New("inactive_timer_sec is required")
	}

	return management.Settings{
		Issuer:             req.GetIssuer(),
		Audience:           req.GetAudience(),
		JWKSURL:            req.GetJwksUrl(),
		RequiredScope:      req.GetRequiredScope(),
		GuardedPortsRange:  req.GetGuardedPortsRange(),
		Iface:              req.GetIface(),
		HandshakeWindowSec: int(req.GetHandshakeWindowSec()),
		InactiveTimerSec:   int(req.GetInactiveTimerSec()),
	}, nil
}

func upsertResponse(
	message string,
	stored management.StoredSettings,
) (*grpcv1.UpsertManagementSettingsResponse, error) {
	handshakeWindowSec, err := toInt32(stored.HandshakeWindowSec)
	if err != nil {
		return nil, fmt.Errorf("convert handshake window: %w", err)
	}
	inactiveTimerSec, err := toInt32(stored.InactiveTimerSec)
	if err != nil {
		return nil, fmt.Errorf("convert inactive timer: %w", err)
	}

	return &grpcv1.UpsertManagementSettingsResponse{
		Message:            message,
		AuthConfigured:     stored.Issuer != "" && stored.JWKSURL != "",
		RuntimeAttached:    stored.Runtime.Attached,
		RuntimeIface:       stored.Runtime.Iface,
		Issuer:             stored.Issuer,
		Audience:           stored.Audience,
		JwksUrl:            stored.JWKSURL,
		RequiredScope:      stored.RequiredScope,
		GuardedPortsRange:  stored.GuardedPortsRange,
		Iface:              stored.Iface,
		HandshakeWindowSec: handshakeWindowSec,
		InactiveTimerSec:   inactiveTimerSec,
		UpdatedAt:          timestamppb.New(stored.UpdatedAt.UTC()),
	}, nil
}

func extractIPv4(ctx context.Context, override string) (net.IP, error) {
	if candidate := strings.TrimSpace(override); candidate != "" {
		ip := net.ParseIP(candidate)
		if ip == nil || ip.To4() == nil {
			return nil, errors.New("IPv4 address required")
		}

		return ip.To4(), nil
	}

	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo == nil || peerInfo.Addr == nil {
		return nil, errors.New("IPv4 address required")
	}

	host, _, err := net.SplitHostPort(peerInfo.Addr.String())
	if err != nil {
		host = peerInfo.Addr.String()
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return nil, errors.New("IPv4 address required")
	}

	return ip.To4(), nil
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

func metadataValue(ctx context.Context, key string) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	values := md.Get(key)
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}

	return ""
}

func logMutationRequestSource(ctx context.Context, operation string, fullMethod string) {
	log.Info().
		Str("operation", operation).
		Str("method", "gRPC").
		Str("path", fullMethod).
		Str("source_ip", sourceIPFromContext(ctx)).
		Msg("Mutation request source recorded")
}

func logMutationAuthError(ctx context.Context, operation string, fullMethod string) {
	log.Warn().
		Str("operation", operation).
		Str("method", "gRPC").
		Str("path", fullMethod).
		Str("source_ip", sourceIPFromContext(ctx)).
		Msg("Mutation request auth error")
}

func sourceIPFromContext(ctx context.Context) string {
	peerInfo, ok := peer.FromContext(ctx)
	if !ok || peerInfo == nil || peerInfo.Addr == nil {
		return "unknown"
	}

	remote := strings.TrimSpace(peerInfo.Addr.String())
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

func settingsNotFoundCode(options authorizationOptions) codes.Code {
	if options.SettingsNotFoundCode != 0 {
		return options.SettingsNotFoundCode
	}

	return codes.Unavailable
}

func settingsNotFoundMessage(options authorizationOptions) string {
	if options.SettingsNotFoundMessage != "" {
		return options.SettingsNotFoundMessage
	}

	return messageAuthUnavailable
}

func authorizationUnavailableCode(options authorizationOptions) codes.Code {
	if options.AuthorizationUnavailableCode != 0 {
		return options.AuthorizationUnavailableCode
	}

	return codes.Unavailable
}

func authorizationUnavailableMessage(options authorizationOptions) string {
	if options.AuthorizationUnavailableBody != "" {
		return options.AuthorizationUnavailableBody
	}

	return messageAuthUnavailable
}

func authorizationFailureMessage(options authorizationOptions) string {
	if options.AuthorizationFailureBody != "" {
		return options.AuthorizationFailureBody
	}

	return defaultAuthFailureResponse
}

func toUint16Port(port uint32) (uint16, error) {
	if port > maxPort {
		return 0, errors.New("valid port number required")
	}

	return uint16(port), nil
}

func toInt32(value int) (int32, error) {
	if value < math.MinInt32 || value > math.MaxInt32 {
		return 0, fmt.Errorf("value out of int32 range: %d", value)
	}

	return int32(value), nil
}

func grpcStatusError(code codes.Code, message string) error {
	//nolint:wrapcheck // transport-level статусная ошибка возвращается в gRPC pipeline напрямую.
	return status.Error(code, message)
}

const maxPort = 65535
