package management

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const (
	minUserPort = 1023
	maxPort     = 65535
)

var (
	ErrInvalidIssuer            = errors.New("invalid issuer")
	ErrInvalidAudience          = errors.New("invalid audience")
	ErrInvalidJWKSURL           = errors.New("invalid jwks url")
	ErrInvalidRequiredScope     = errors.New("invalid required scope")
	ErrInvalidGuardedPortsRange = errors.New("invalid guarded ports range")
	ErrInvalidIface             = errors.New("invalid network interface")
	ErrInvalidAccessToken       = errors.New("invalid access token")
	ErrAuthorizationUnavailable = errors.New("authorization unavailable")
	ErrInvalidBootstrapToken    = errors.New("invalid bootstrap token")
	ErrBootstrapLocked          = errors.New("management settings are locked")
	ErrBootstrapNotConfigured   = errors.New("management bootstrap is not configured")
	ErrSettingsNotFound         = errors.New("management settings not found")
)

type Options struct {
	BootstrapToken string
}

// Service orchestrates management settings validation, persistence and authorization.
type Service struct {
	repository     Repository
	verifier       Verifier
	bootstrapToken string
}

// New creates a new management Service.
func New(repository Repository, verifier Verifier, options Options) *Service {
	return &Service{
		repository:     repository,
		verifier:       verifier,
		bootstrapToken: strings.TrimSpace(options.BootstrapToken),
	}
}

// SaveSettings validates management settings, verifies JWKS provider and stores settings in repository.
func (s *Service) SaveSettings(ctx context.Context, settings Settings) (StoredSettings, error) {
	if s.repository == nil {
		return StoredSettings{}, errors.New("repository is nil")
	}
	if s.verifier == nil {
		return StoredSettings{}, errors.New("verifier is nil")
	}

	normalized, err := normalizeAndValidate(settings)
	if err != nil {
		return StoredSettings{}, err
	}

	if err := s.verifier.ValidateSettings(ctx, normalized); err != nil {
		return StoredSettings{}, fmt.Errorf("%w: %s", ErrInvalidJWKSURL, err.Error())
	}

	stored, err := s.repository.SaveSettings(ctx, normalized)
	if err != nil {
		return StoredSettings{}, fmt.Errorf("save management settings: %w", err)
	}

	return stored, nil
}

// GetSettings reads current management settings from repository.
func (s *Service) GetSettings(ctx context.Context) (StoredSettings, error) {
	if s.repository == nil {
		return StoredSettings{}, errors.New("repository is nil")
	}

	stored, err := s.repository.LoadSettings(ctx)
	if err != nil {
		if errors.Is(err, ErrSettingsNotFound) {
			return StoredSettings{}, ErrSettingsNotFound
		}

		return StoredSettings{}, fmt.Errorf("get management settings: %w", err)
	}

	return stored, nil
}

// AuthorizeAllow validates incoming JWT access token for /allow operation.
func (s *Service) AuthorizeAllow(ctx context.Context, accessToken string) error {
	if s.repository == nil {
		return errors.New("repository is nil")
	}
	if s.verifier == nil {
		return errors.New("verifier is nil")
	}

	token := strings.TrimSpace(accessToken)
	if token == "" {
		return fmt.Errorf("%w: token cannot be empty", ErrInvalidAccessToken)
	}

	stored, err := s.repository.LoadSettings(ctx)
	if err != nil {
		if errors.Is(err, ErrSettingsNotFound) {
			return ErrSettingsNotFound
		}

		return fmt.Errorf("load management settings: %w", err)
	}

	if err := s.verifier.VerifyAllowToken(ctx, stored.Settings, token); err != nil {
		switch {
		case errors.Is(err, ErrInvalidAccessToken):
			return ErrInvalidAccessToken
		case errors.Is(err, ErrAuthorizationUnavailable):
			return ErrAuthorizationUnavailable
		default:
			return fmt.Errorf("verify allow token: %w", err)
		}
	}

	return nil
}

// AuthorizeSettingsBootstrap validates one-time bootstrap token and ensures settings are not configured yet.
func (s *Service) AuthorizeSettingsBootstrap(ctx context.Context, bootstrapToken string) error {
	if s.repository == nil {
		return errors.New("repository is nil")
	}

	if s.bootstrapToken == "" {
		return ErrBootstrapNotConfigured
	}

	stored, err := s.repository.LoadSettings(ctx)
	if err == nil {
		_ = stored

		return ErrBootstrapLocked
	}
	if !errors.Is(err, ErrSettingsNotFound) {
		return fmt.Errorf("load management settings: %w", err)
	}

	candidate := strings.TrimSpace(bootstrapToken)
	if candidate == "" {
		return ErrInvalidBootstrapToken
	}
	if subtle.ConstantTimeCompare([]byte(candidate), []byte(s.bootstrapToken)) != 1 {
		return ErrInvalidBootstrapToken
	}

	return nil
}

func normalizeAndValidate(settings Settings) (Settings, error) {
	issuer := strings.TrimSpace(settings.Issuer)
	if err := validateIssuer(issuer); err != nil {
		return Settings{}, fmt.Errorf("%w: %s", ErrInvalidIssuer, err.Error())
	}

	audience := strings.TrimSpace(settings.Audience)
	if err := validateAudience(audience); err != nil {
		return Settings{}, fmt.Errorf("%w: %s", ErrInvalidAudience, err.Error())
	}

	jwksURL := strings.TrimSpace(settings.JWKSURL)
	if err := validateJWKSURL(jwksURL); err != nil {
		return Settings{}, fmt.Errorf("%w: %s", ErrInvalidJWKSURL, err.Error())
	}

	requiredScope := strings.TrimSpace(settings.RequiredScope)
	if err := validateRequiredScope(requiredScope); err != nil {
		return Settings{}, fmt.Errorf("%w: %s", ErrInvalidRequiredScope, err.Error())
	}

	guardedPortsRange := strings.TrimSpace(settings.GuardedPortsRange)
	if err := validateGuardedPortsRange(guardedPortsRange); err != nil {
		return Settings{}, fmt.Errorf("%w: %s", ErrInvalidGuardedPortsRange, err.Error())
	}

	iface := strings.TrimSpace(settings.Iface)
	if err := validateIface(iface); err != nil {
		return Settings{}, fmt.Errorf("%w: %s", ErrInvalidIface, err.Error())
	}

	return Settings{
		Issuer:            issuer,
		Audience:          audience,
		JWKSURL:           jwksURL,
		RequiredScope:     requiredScope,
		GuardedPortsRange: guardedPortsRange,
		Iface:             iface,
	}, nil
}

func validateIssuer(issuer string) error {
	if issuer == "" {
		return errors.New("issuer cannot be empty")
	}

	parsed, err := url.Parse(issuer)
	if err != nil {
		return fmt.Errorf("parse issuer URL: %w", err)
	}
	if !parsed.IsAbs() {
		return errors.New("issuer must be an absolute URL")
	}
	if parsed.Scheme != "https" {
		return errors.New("issuer URL scheme must be https")
	}
	if parsed.Host == "" {
		return errors.New("issuer host cannot be empty")
	}

	return nil
}

func validateAudience(audience string) error {
	if audience == "" {
		return errors.New("audience cannot be empty")
	}

	return nil
}

func validateJWKSURL(jwksURL string) error {
	if jwksURL == "" {
		return errors.New("jwks URL cannot be empty")
	}

	parsed, err := url.Parse(jwksURL)
	if err != nil {
		return fmt.Errorf("parse jwks URL: %w", err)
	}
	if !parsed.IsAbs() {
		return errors.New("jwks URL must be an absolute URL")
	}
	if parsed.Scheme != "https" {
		return errors.New("jwks URL scheme must be https")
	}
	if parsed.Host == "" {
		return errors.New("jwks URL host cannot be empty")
	}

	return nil
}

func validateRequiredScope(scope string) error {
	if scope == "" {
		return errors.New("required scope cannot be empty")
	}
	if strings.ContainsAny(scope, " \t\n\r\v\f") {
		return errors.New("required scope cannot contain whitespace")
	}

	return nil
}

func validateIface(iface string) error {
	if iface == "" {
		return errors.New("interface name cannot be empty")
	}

	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface '%s' not found: %w", iface, err)
	}

	if ifaceObj.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface '%s' is down", iface)
	}

	return nil
}

func validateGuardedPortsRange(rangeStr string) error {
	if rangeStr == "" {
		return errors.New("guarded ports range cannot be empty")
	}

	if strings.Contains(rangeStr, " ") {
		return errors.New("guarded ports range cannot contain spaces")
	}

	if strings.ContainsAny(rangeStr, "\t\n\r\v\f") {
		return errors.New("guarded ports range cannot contain whitespace")
	}

	const rangeParts = 2
	parts := strings.Split(rangeStr, "-")
	if len(parts) != rangeParts {
		return errors.New("guarded ports range format must be 'start-end'")
	}

	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid start port: %w", err)
	}

	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid end port: %w", err)
	}

	if start < minUserPort {
		return fmt.Errorf("start port %d is less than minimum %d", start, minUserPort)
	}

	if end < minUserPort {
		return fmt.Errorf("end port %d is less than minimum %d", end, minUserPort)
	}

	if start > maxPort {
		return fmt.Errorf("start port %d exceeds maximum %d", start, maxPort)
	}

	if end > maxPort {
		return fmt.Errorf("end port %d exceeds maximum %d", end, maxPort)
	}

	if start > end {
		return fmt.Errorf("start port %d is greater than end port %d", start, end)
	}

	return nil
}
