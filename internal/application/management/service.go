package management

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	minUserPort = 1023
	maxPort     = 65535
)

var (
	// ErrInvalidToken is returned when management token is invalid.
	ErrInvalidToken = errors.New("invalid management token")
	// ErrInvalidGuardedPortsRange is returned when ports range is invalid.
	ErrInvalidGuardedPortsRange = errors.New("invalid guarded ports range")
	// ErrInvalidIface is returned when network interface is invalid.
	ErrInvalidIface = errors.New("invalid network interface")
	// ErrSettingsNotFound is returned when settings are not yet persisted.
	ErrSettingsNotFound = errors.New("management settings not found")
)

// Service orchestrates management settings validation and persistence.
type Service struct {
	repository Repository
}

// New creates a new management Service.
func New(repository Repository) *Service {
	return &Service{
		repository: repository,
	}
}

// SaveSettings validates management settings and stores them in repository.
func (s *Service) SaveSettings(ctx context.Context, settings Settings) (StoredSettings, error) {
	if s.repository == nil {
		return StoredSettings{}, errors.New("repository is nil")
	}

	normalized, err := normalizeAndValidate(settings)
	if err != nil {
		return StoredSettings{}, err
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

func normalizeAndValidate(settings Settings) (Settings, error) {
	token := strings.TrimSpace(settings.Token)
	if token == "" {
		return Settings{}, fmt.Errorf("%w: token cannot be empty", ErrInvalidToken)
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
		Token:             token,
		GuardedPortsRange: guardedPortsRange,
		Iface:             iface,
	}, nil
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

	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 { //nolint:mnd
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
