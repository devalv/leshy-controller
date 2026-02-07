package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Config struct {
	Debug              bool   `yaml:"debug"`
	BPFProgramPath     string `yaml:"bpf_program_path"`
	BPFPinPath         string `yaml:"bpf_pin_path"`
	SettingsDBPath     string `yaml:"db_path"`
	Iface              string `yaml:"iface"`
	APIListenAddr      string `yaml:"api_listen_addr"`
	GuardedPortsRange  string `yaml:"guarded_ports_range"`
	HandshakeWindowSec int    `yaml:"handshake_window_sec"`
	ShutdownTimeoutSec int    `yaml:"shutdown_timeout_sec"`

	ConfigPath string
}

// Проверяем путь до конфига.
func validateConfigPath(path string) error {
	s, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to validate config path: %w", err)
	}

	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a file", path)
	}

	return nil
}

// Проверяем путь до BPF программы (например, cbpf/l4_filter.o).
func validateBPFProgramPath(path string) error {
	if path == "" {
		return errors.New("BPF program path cannot be empty")
	}

	s, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to validate BPF program path: %w", err)
	}

	// Проверяем, что это не директория
	if s.IsDir() {
		return fmt.Errorf("'%s' is a directory, not a file", path)
	}

	// Получаем имя файла с расширением
	filename := filepath.Base(path)

	// Проверяем расширение
	if !strings.HasSuffix(filename, ".o") {
		return fmt.Errorf("BPF program '%s' must have `.o` extension", filename)
	}

	// Проверяем имя файла
	expectedName := "l4_filter.o"
	if filename != expectedName {
		return fmt.Errorf("BPF program must be named '%s', got '%s'", expectedName, filename)
	}

	return nil
}

// Проверяем путь до BPF пина (например, /sys/fs/bpf/).
func validateBPFPinPath(path string) error {
	if path == "" {
		return errors.New("BPF pin path cannot be empty")
	}

	s, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to validate BPF pin path: %w", err)
	}

	// Проверяем, что это не директория
	if !s.IsDir() {
		return fmt.Errorf("'%s' should be a directory", path)
	}

	return nil
}

// Проверяем значение интерфейса.
func validateIface(iface string) error {
	if iface == "" {
		return errors.New("interface name cannot be empty")
	}

	// Проверка существования в системе
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface '%s' not found: %w", iface, err)
	}

	// Проверка что интерфейс up
	if ifaceObj.Flags&net.FlagUp == 0 {
		return fmt.Errorf("interface '%s' is down", iface)
	}

	return nil
}

// Проверяем значение адреса API.
func validateAPIListenAddr(addr string) error {
	if addr == "" {
		return errors.New("API listen address cannot be empty")
	}

	// Проверяем формат "host:port"
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format, expected 'host:port': %w", err)
	}

	// Проверка порта
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port number '%s': %w", port, err)
	}

	if portNum < 1023 || portNum > 65535 {
		return fmt.Errorf("port must be between 1023 and 65535, got %d", portNum)
	}

	// Простая проверка через net.ResolveTCPAddr
	_, err = net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return fmt.Errorf("invalid listen address '%s': %w", addr, err)
	}

	return nil
}

// Проверяем значение диапазона портов.
func validateGuardedPortsRange(rangeStr string) error {
	const (
		minPort = 1023
		maxPort = 65535
	)
	if rangeStr == "" {
		return errors.New("GuardedPortsRange cannot be empty")
	}

	// Проверка на наличие пробелов в любой части строки
	if strings.Contains(rangeStr, " ") {
		return fmt.Errorf("GuardedPortsRange cannot contain spaces, got '%s'", rangeStr)
	}

	// Проверка на другие whitespace символы
	if strings.ContainsAny(rangeStr, "\t\n\r\v\f") {
		return errors.New("GuardedPortsRange cannot contain whitespace characters")
	}

	// Проверяем формат "начало-конец"
	parts := strings.Split(rangeStr, "-")
	if len(parts) != 2 { //nolint:mnd
		return fmt.Errorf("invalid range format, expected 'start-end', got '%s'", rangeStr)
	}

	// Проверяем что части не пустые
	if parts[0] == "" {
		return fmt.Errorf("start port cannot be empty in range '%s'", rangeStr)
	}

	if parts[1] == "" {
		return fmt.Errorf("end port cannot be empty in range '%s'", rangeStr)
	}

	// Парсим начальный порт без удаления пробелов (их уже проверили)
	start, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("invalid start port '%s': %w", parts[0], err)
	}

	// Парсим конечный порт без удаления пробелов
	end, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("invalid end port '%s': %w", parts[1], err)
	}

	// Проверяем минимальное значение
	if start < minPort {
		return fmt.Errorf("start port %d is less than minimum allowed 1023", start)
	}

	if end < minPort {
		return fmt.Errorf("end port %d is less than minimum allowed 1023", end)
	}

	// Проверяем максимальное значение
	if start > maxPort {
		return fmt.Errorf("start port %d exceeds maximum 65535", start)
	}

	if end > maxPort {
		return fmt.Errorf("end port %d exceeds maximum 65535", end)
	}

	// Проверяем что начальный порт не больше конечного
	if start > end {
		return fmt.Errorf("start port %d is greater than end port %d", start, end)
	}

	return nil
}

// Проверяем значение окна установки соединения клиента.
func validateHandshakeWindowSecs(secs int) error {
	const (
		minHandshakeWindowSecs = 1
		maxHandshakeWindowSecs = 10800
	)
	if secs < minHandshakeWindowSecs {
		return fmt.Errorf("HandshakeWindowSec must be at least 1, got %d", secs)
	}

	if secs > maxHandshakeWindowSecs {
		return fmt.Errorf("HandshakeWindowSec cannot exceed 10800 seconds (3 hours), got %d", secs)
	}

	return nil
}

// Проверяем значение завершения приложения.
func validateShutdownTimeout(secs int) error {
	const (
		minShutdownTimeoutSecs = 1
		maxShutdownTimeoutSecs = 60
	)
	if secs < minShutdownTimeoutSecs {
		return fmt.Errorf("shutdown_timeout_sec must be at least 1, got %d", secs)
	}
	if secs > maxShutdownTimeoutSecs {
		return fmt.Errorf("shutdown_timeout_sec cannot exceed 10800 seconds (3 hours), got %d", secs)
	}

	return nil
}

// Проверяем доступность пути с БД.
func validateSettingsDBPath(path string) error {
	if path == "" {
		return errors.New("settings DB path cannot be empty")
	}

	s, err := os.Stat(path)
	if err == nil {
		// Проверяем, что это не директория
		if s.IsDir() {
			return fmt.Errorf("'%s' is a directory, not a file", path)
		}

		return nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		if errors.Is(err, syscall.ENOTDIR) {
			return fmt.Errorf("'%s' is not a directory", filepath.Dir(path))
		}

		return fmt.Errorf("failed to validate DB path: %w", err)
	}

	parentDir := filepath.Dir(path)
	if parentDir == "." || parentDir == "" {
		return nil
	}

	parentStat, parentErr := os.Stat(parentDir)
	if parentErr == nil && !parentStat.IsDir() {
		return fmt.Errorf("'%s' is not a directory", parentDir)
	}
	if parentErr != nil && !errors.Is(parentErr, os.ErrNotExist) {
		return fmt.Errorf("failed to validate DB parent directory: %w", parentErr)
	}

	return nil
}

// Читаем аргументы запуска приложения.
func parseFlags() (path string, err error) {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "./config.yml", "path to config file")
	flag.Parse()

	if err := validateConfigPath(cfgPath); err != nil {
		return "", fmt.Errorf("failed to parse config path: %w", err)
	}

	return cfgPath, nil
}

func NewConfig() (*Config, error) {
	cfgPath, err := parseFlags()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to parse flags")
	}

	var cfg Config
	err = cleanenv.ReadConfig(cfgPath, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}
	cfg.ConfigPath = cfgPath
	cfg.ConfigureLogger()

	if err := cfg.Validate(); err != nil {
		log.Fatal().Err(err).Msg("failed to validate config")
	}

	return &cfg, nil
}

// Validate валидирует прочитанных значений конфигурации.
func (cfg *Config) Validate() error {
	var errs []error

	if err := validateBPFProgramPath(cfg.BPFProgramPath); err != nil {
		errs = append(errs, fmt.Errorf("BPFProgramPath: %w", err))
	}

	if err := validateBPFPinPath(cfg.BPFPinPath); err != nil {
		errs = append(errs, fmt.Errorf("BPFPinPath: %w", err))
	}

	if err := validateIface(cfg.Iface); err != nil {
		errs = append(errs, fmt.Errorf("iface: %w", err))
	}

	if err := validateAPIListenAddr(cfg.APIListenAddr); err != nil {
		errs = append(errs, fmt.Errorf("APIListenAddr: %w", err))
	}

	if err := validateGuardedPortsRange(cfg.GuardedPortsRange); err != nil {
		errs = append(errs, fmt.Errorf("GuardedPortsRange: %w", err))
	}

	if err := validateHandshakeWindowSecs(cfg.HandshakeWindowSec); err != nil {
		errs = append(errs, fmt.Errorf("HandshakeWindowSec: %w", err))
	}

	if err := validateShutdownTimeout(cfg.ShutdownTimeoutSec); err != nil {
		errs = append(errs, fmt.Errorf("ShutdownTimeoutSec: %w", err))
	}

	if err := validateSettingsDBPath(cfg.SettingsDBPath); err != nil {
		errs = append(errs, fmt.Errorf("SettingsDBPath: %w", err))
	}

	// Объединяем все ошибки в одну
	return errors.Join(errs...)
}

// ConfigureLogger конфигурирует логгер.
func (cfg *Config) ConfigureLogger() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	if cfg.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug mode enabled")
	}
}
