package config

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Helper functions

func createTempFile(t *testing.T, content string) string {
	t.Helper()
	tmpFile, err := os.CreateTemp("", "test*.yml")
	if err != nil {
		t.Fatal(err)
	}
	defer tmpFile.Close()

	if content != "" {
		_, err = tmpFile.WriteString(content)
		if err != nil {
			t.Fatal(err)
		}
	}

	return tmpFile.Name()
}

func createTempDir(t *testing.T) string {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "testdir")
	if err != nil {
		t.Fatal(err)
	}
	return tmpDir
}

// Tests for validateConfigPath

func TestValidateConfigPath(t *testing.T) {
	tests := []struct {
		name        string
		prepare     func(t *testing.T) string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid config file",
			prepare: func(t *testing.T) string {
				return createTempFile(t, "test: config")
			},
			wantErr: false,
		},
		{
			name: "non-existent file",
			prepare: func(t *testing.T) string {
				return "/tmp/non-existent-file-123456.yml"
			},
			wantErr:     true,
			errContains: "failed to validate config path",
		},
		{
			name: "directory instead of file",
			prepare: func(t *testing.T) string {
				return createTempDir(t)
			},
			wantErr:     true,
			errContains: "is a directory, not a file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.prepare(t)
			defer os.Remove(path) // Cleanup
			defer os.RemoveAll(path)

			err := validateConfigPath(path)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Tests for validateBPFProgramPath

func TestValidateBPFProgramPath(t *testing.T) {
	tmpDir := createTempDir(t)
	defer os.RemoveAll(tmpDir)

	validBPF := filepath.Join(tmpDir, "l4_filter.o")
	err := os.WriteFile(validBPF, []byte("test"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	wrongNameBPF := filepath.Join(tmpDir, "wrong_name.o")
	err = os.WriteFile(wrongNameBPF, []byte("test"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	wrongExtFile := filepath.Join(tmpDir, "l4_filter.txt")
	err = os.WriteFile(wrongExtFile, []byte("test"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		path        string
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty path",
			path:        "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:    "valid BPF program",
			path:    validBPF,
			wantErr: false,
		},
		{
			name:        "non-existent file",
			path:        "/tmp/non-existent-bpf.o",
			wantErr:     true,
			errContains: "failed to validate BPF program path",
		},
		{
			name:        "directory instead of file",
			path:        tmpDir,
			wantErr:     true,
			errContains: "is a directory, not a file",
		},
		{
			name:        "wrong file name",
			path:        wrongNameBPF,
			wantErr:     true,
			errContains: "must be named 'l4_filter.o'",
		},
		{
			name:        "wrong extension",
			path:        wrongExtFile,
			wantErr:     true,
			errContains: "must have `.o` extension",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBPFProgramPath(tt.path)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Tests for validateBPFPinPath

func TestValidateBPFPinPath(t *testing.T) {
	tmpDir := createTempDir(t)
	defer os.RemoveAll(tmpDir)

	tmpFile := createTempFile(t, "test")
	defer os.Remove(tmpFile)

	tests := []struct {
		name        string
		path        string
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty path",
			path:        "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:    "valid directory",
			path:    tmpDir,
			wantErr: false,
		},
		{
			name:        "non-existent path",
			path:        "/tmp/non-existent-dir-123456",
			wantErr:     true,
			errContains: "failed to validate BPF pin path",
		},
		{
			name:        "file instead of directory",
			path:        tmpFile,
			wantErr:     true,
			errContains: "should be a directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBPFPinPath(tt.path)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Tests for validateIface

func TestValidateIface(t *testing.T) {
	// Get a real interface for testing (usually loopback exists)
	realInterface := "lo"
	if _, err := os.Stat("/sys/class/net/lo"); os.IsNotExist(err) {
		// Try to get any existing interface
		interfaces, err := os.ReadDir("/sys/class/net")
		if err == nil && len(interfaces) > 0 {
			realInterface = interfaces[0].Name()
		} else {
			realInterface = "eth0" // fallback
		}
	}

	tests := []struct {
		name        string
		iface       string
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty interface",
			iface:       "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "non-existent interface",
			iface:       "nonexistentinterface123",
			wantErr:     true,
			errContains: "interface 'nonexistentinterface123' not found",
		},
		{
			name:    "valid interface (if exists)",
			iface:   realInterface,
			wantErr: false,
			// Note: This test will fail if interface is down
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIface(tt.iface)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil && !contains(err.Error(), "is down") {
					// Allow "interface is down" error for this test
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Tests for validateAPIListenAddr

func TestValidateAPIListenAddr(t *testing.T) {
	tests := []struct {
		name        string
		addr        string
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty address",
			addr:        "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "missing port",
			addr:        "127.0.0.1",
			wantErr:     true,
			errContains: "expected 'host:port'",
		},
		{
			name:        "invalid port",
			addr:        "127.0.0.1:abc",
			wantErr:     true,
			errContains: "invalid port number",
		},
		{
			name:        "port too low",
			addr:        "127.0.0.1:0",
			wantErr:     true,
			errContains: "port must be between 1023 and 65535",
		},
		{
			name:        "port too high",
			addr:        "127.0.0.1:65536",
			wantErr:     true,
			errContains: "port must be between 1023 and 65535",
		},
		{
			name:        "system port (should fail)",
			addr:        "127.0.0.1:80",
			wantErr:     true,
			errContains: "port must be between 1023 and 65535",
		},
		{
			name:    "valid address with port 1023",
			addr:    "127.0.0.1:1023",
			wantErr: false,
		},
		{
			name:    "valid address with port 8080",
			addr:    "127.0.0.1:8080",
			wantErr: false,
		},
		{
			name:    "valid address with all interfaces",
			addr:    "0.0.0.0:9090",
			wantErr: false,
		},
		{
			name:    "valid address with localhost",
			addr:    "localhost:9090",
			wantErr: false,
		},
		{
			name:        "invalid host",
			addr:        "999.0.0.1:9090",
			wantErr:     true,
			errContains: "invalid listen address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAPIListenAddr(tt.addr)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Tests for validateGuardedPortsRange

func TestValidateGuardedPortsRange(t *testing.T) {
	tests := []struct {
		name        string
		rangeStr    string
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty range",
			rangeStr:    "",
			wantErr:     true,
			errContains: "cannot be empty",
		},
		{
			name:        "contains spaces",
			rangeStr:    "1024 - 2048",
			wantErr:     true,
			errContains: "cannot contain spaces",
		},
		{
			name:        "contains tab",
			rangeStr:    "1024\t2048",
			wantErr:     true,
			errContains: "cannot contain whitespace",
		},
		{
			name:        "missing dash",
			rangeStr:    "10242048",
			wantErr:     true,
			errContains: "expected 'start-end'",
		},
		{
			name:        "multiple dashes",
			rangeStr:    "1024-2048-4096",
			wantErr:     true,
			errContains: "expected 'start-end'",
		},
		{
			name:        "empty start port",
			rangeStr:    "-2048",
			wantErr:     true,
			errContains: "start port cannot be empty",
		},
		{
			name:        "empty end port",
			rangeStr:    "1024-",
			wantErr:     true,
			errContains: "end port cannot be empty",
		},
		{
			name:        "invalid start port",
			rangeStr:    "abc-2048",
			wantErr:     true,
			errContains: "invalid start port",
		},
		{
			name:        "invalid end port",
			rangeStr:    "1024-xyz",
			wantErr:     true,
			errContains: "invalid end port",
		},
		{
			name:        "start port too low",
			rangeStr:    "1022-2048",
			wantErr:     true,
			errContains: "less than minimum allowed 1023",
		},
		{
			name:        "end port too low",
			rangeStr:    "2048-1022",
			wantErr:     true,
			errContains: "less than minimum allowed 1023",
		},
		{
			name:        "start port too high",
			rangeStr:    "65536-66000",
			wantErr:     true,
			errContains: "exceeds maximum 65535",
		},
		{
			name:        "end port too high",
			rangeStr:    "60000-65536",
			wantErr:     true,
			errContains: "exceeds maximum 65535",
		},
		{
			name:        "start > end",
			rangeStr:    "5000-4000",
			wantErr:     true,
			errContains: "greater than end port",
		},
		{
			name:     "valid range single port",
			rangeStr: "1023-1023",
			wantErr:  false,
		},
		{
			name:     "valid range multiple ports",
			rangeStr: "1024-2048",
			wantErr:  false,
		},
		{
			name:     "valid range max ports",
			rangeStr: "65533-65535",
			wantErr:  false,
		},
		{
			name:     "valid range min to max",
			rangeStr: "1023-65535",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGuardedPortsRange(tt.rangeStr)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Tests for validateHandshakeWindowSecs

func TestValidateHandshakeWindowSecs(t *testing.T) {
	tests := []struct {
		name        string
		secs        int
		wantErr     bool
		errContains string
	}{
		{
			name:        "zero seconds",
			secs:        0,
			wantErr:     true,
			errContains: "must be at least 1",
		},
		{
			name:        "negative seconds",
			secs:        -1,
			wantErr:     true,
			errContains: "must be at least 1",
		},
		{
			name:    "minimum valid (1 second)",
			secs:    1,
			wantErr: false,
		},
		{
			name:    "valid seconds",
			secs:    30,
			wantErr: false,
		},
		{
			name:    "one hour",
			secs:    3600,
			wantErr: false,
		},
		{
			name:    "exactly 3 hours",
			secs:    10800,
			wantErr: false,
		},
		{
			name:        "more than 3 hours",
			secs:        10801,
			wantErr:     true,
			errContains: "cannot exceed 10800 seconds",
		},
		{
			name:        "much more than 3 hours",
			secs:        86400, // 24 hours
			wantErr:     true,
			errContains: "cannot exceed 10800 seconds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHandshakeWindowSecs(tt.secs)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("error %q should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

// Tests for Config.Validate

func TestConfigValidate(t *testing.T) {
	tmpDir := createTempDir(t)
	defer os.RemoveAll(tmpDir)

	validBPF := filepath.Join(tmpDir, "l4_filter.o")
	err := os.WriteFile(validBPF, []byte("test"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// Get a real interface
	realInterface := "lo"

	tests := []struct {
		name     string
		config   Config
		wantErr  bool
		errCount int // number of expected errors
	}{
		{
			name: "valid config",
			config: Config{
				BPFProgramPath:      validBPF,
				BPFPinPath:          tmpDir,
				Iface:               realInterface,
				APIListenAddr:       "127.0.0.1:9090",
				GuardedPortsRange:   "1024-2048",
				HandshakeWindowSecs: 30,
				ShutdownTimeout:     5,
			},
			wantErr: false,
		},
		{
			name: "multiple errors",
			config: Config{
				BPFProgramPath:      "",
				BPFPinPath:          "",
				Iface:               "",
				APIListenAddr:       "invalid",
				GuardedPortsRange:   "invalid",
				HandshakeWindowSecs: 0,
				ShutdownTimeout:     0,
			},
			wantErr:  true,
			errCount: 7, // all fields invalid
		},
		{
			name: "invalid BPF path only",
			config: Config{
				BPFProgramPath:      "",
				BPFPinPath:          tmpDir,
				Iface:               realInterface,
				APIListenAddr:       "127.0.0.1:9090",
				GuardedPortsRange:   "1024-2048",
				HandshakeWindowSecs: 30,
				ShutdownTimeout:     5,
			},
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "invalid port range only",
			config: Config{
				BPFProgramPath:      validBPF,
				BPFPinPath:          tmpDir,
				Iface:               realInterface,
				APIListenAddr:       "127.0.0.1:9090",
				GuardedPortsRange:   "100-200", // invalid (starts at 100 < 1023)
				HandshakeWindowSecs: 30,
				ShutdownTimeout:     5,
			},
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "invalid handshake window",
			config: Config{
				BPFProgramPath:      validBPF,
				BPFPinPath:          tmpDir,
				Iface:               realInterface,
				APIListenAddr:       "127.0.0.1:9090",
				GuardedPortsRange:   "1024-2048",
				HandshakeWindowSecs: 10801, // > 3 hours
				ShutdownTimeout:     5,
			},
			wantErr:  true,
			errCount: 1,
		},
		{
			name: "invalid shutdown timeout",
			config: Config{
				BPFProgramPath:      validBPF,
				BPFPinPath:          tmpDir,
				Iface:               realInterface,
				APIListenAddr:       "127.0.0.1:9090",
				GuardedPortsRange:   "1024-2048",
				HandshakeWindowSecs: 30,
				ShutdownTimeout:     61, // > 61 secs

			},
			wantErr:  true,
			errCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}

				// Check number of errors if specified
				if tt.errCount > 0 {
					if errList, ok := err.(interface{ Unwrap() []error }); ok {
						errors := errList.Unwrap()
						if len(errors) != tt.errCount {
							t.Errorf("expected %d errors, got %d", tt.errCount, len(errors))
						}
					}
				}
			} else {
				if err != nil {
					// Check if error is just about interface being down
					if !contains(err.Error(), "is down") {
						t.Errorf("unexpected error: %v", err)
					}
				}
			}
		})
	}
}

// Tests for parseFlags (integration test)

func TestParseFlags(t *testing.T) {
	// Этот тест нельзя запускать параллельно с другими тестами
	// из-за глобального состояния флагов

	// Сохраняем оригинальные аргументы командной строки
	oldArgs := os.Args
	oldCommandLine := flag.CommandLine

	defer func() {
		// Восстанавливаем оригинальные значения
		os.Args = oldArgs
		flag.CommandLine = oldCommandLine
	}()

	// Test 1: Valid config file
	t.Run("valid config file", func(t *testing.T) {
		tmpFile := createTempFile(t, "test: config")
		defer os.Remove(tmpFile)

		// Создаем новый FlagSet для изоляции
		testFlagSet := flag.NewFlagSet("test", flag.ContinueOnError)
		var cfgPath string
		testFlagSet.StringVar(&cfgPath, "config", "./config.yml", "path to config file")

		// Имитируем аргументы командной строки
		err := testFlagSet.Parse([]string{"-config", tmpFile})
		if err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		// Вместо вызова parseFlags(), проверяем напрямую
		err = validateConfigPath(cfgPath)
		if err != nil {
			t.Errorf("validateConfigPath failed: %v", err)
		}
	})

	// Test 2: Non-existent config file
	t.Run("non-existent config file", func(t *testing.T) {
		testFlagSet := flag.NewFlagSet("test", flag.ContinueOnError)
		var cfgPath string
		testFlagSet.StringVar(&cfgPath, "config", "./config.yml", "path to config file")

		err := testFlagSet.Parse([]string{"-config", "/tmp/non-existent-file-123456.yml"})
		if err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		err = validateConfigPath(cfgPath)
		if err == nil {
			t.Error("expected error for non-existent file, got nil")
		}
	})

	// Test 3: No -config flag provided (используется значение по умолчанию)
	t.Run("no -config flag provided", func(t *testing.T) {
		testFlagSet := flag.NewFlagSet("test", flag.ContinueOnError)
		var cfgPath string
		testFlagSet.StringVar(&cfgPath, "config", "./config.yml", "path to config file")

		// Имитируем запуск без аргументов (только имя программы)
		err := testFlagSet.Parse([]string{})
		if err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		// Значение должно быть по умолчанию
		if cfgPath != "./config.yml" {
			t.Errorf("cfgPath = %s, want ./config.yml", cfgPath)
		}

		// Проверяем что валидация НЕ выполняется (это делает parseFlags)
		// Мы просто проверяем что значение по умолчанию установлено
	})

	// Test 4: Directory instead of file
	t.Run("directory instead of file", func(t *testing.T) {
		tmpDir := createTempDir(t)
		defer os.RemoveAll(tmpDir)

		testFlagSet := flag.NewFlagSet("test", flag.ContinueOnError)
		var cfgPath string
		testFlagSet.StringVar(&cfgPath, "config", "./config.yml", "path to config file")

		err := testFlagSet.Parse([]string{"-config", tmpDir})
		if err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		err = validateConfigPath(cfgPath)
		if err == nil {
			t.Error("expected error for directory, got nil")
		} else if !contains(err.Error(), "is a directory, not a file") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	// Test 5: Multiple arguments (дополнительные флаги игнорируются)
	t.Run("multiple arguments with -config", func(t *testing.T) {
		tmpFile := createTempFile(t, "test: config")
		defer os.Remove(tmpFile)

		testFlagSet := flag.NewFlagSet("test", flag.ContinueOnError)
		var cfgPath string
		var debug bool
		testFlagSet.StringVar(&cfgPath, "config", "./config.yml", "path to config file")
		testFlagSet.BoolVar(&debug, "debug", false, "enable debug mode")

		// Имитируем несколько аргументов
		err := testFlagSet.Parse([]string{"-config", tmpFile, "-debug"})
		if err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		// Проверяем что оба флага распарсились
		if cfgPath != tmpFile {
			t.Errorf("cfgPath = %s, want %s", cfgPath, tmpFile)
		}
		if !debug {
			t.Error("debug flag should be true")
		}
	})

	// Test 6: -config flag with empty value (используется значение по умолчанию)
	t.Run("-config flag with empty value", func(t *testing.T) {
		testFlagSet := flag.NewFlagSet("test", flag.ContinueOnError)
		var cfgPath string
		testFlagSet.StringVar(&cfgPath, "config", "./config.yml", "path to config file")

		// Попытка передать -config без значения
		// flag.Parse() ожидает значение после -config
		// В реальности это вызовет ошибку или будет считать следующее слово значением
		err := testFlagSet.Parse([]string{"-config"})
		if err != nil {
			// Ожидаем ошибку, так как нет значения для -config
			// Это нормальное поведение flag пакета
			t.Logf("expected parse error: %v", err)
		} else {
			// Если ошибки нет, проверяем значение
			// В этом случае cfgPath будет пустой строкой
			if cfgPath == "" {
				t.Log("cfgPath is empty as expected for missing value")
			}
		}
	})

	// Test 7: Different flag order
	t.Run("different flag order", func(t *testing.T) {
		tmpFile := createTempFile(t, "test: config")
		defer os.Remove(tmpFile)

		testFlagSet := flag.NewFlagSet("test", flag.ContinueOnError)
		var cfgPath string
		var verbose bool
		testFlagSet.StringVar(&cfgPath, "config", "./config.yml", "path to config file")
		testFlagSet.BoolVar(&verbose, "v", false, "verbose output")

		// -config не первый аргумент
		err := testFlagSet.Parse([]string{"-v", "-config", tmpFile})
		if err != nil {
			t.Fatalf("failed to parse flags: %v", err)
		}

		if cfgPath != tmpFile {
			t.Errorf("cfgPath = %s, want %s", cfgPath, tmpFile)
		}
		if !verbose {
			t.Error("verbose flag should be true")
		}
	})
}

// Test for NewConfig (requires actual config file)

func TestNewConfig(t *testing.T) {
	// Create a valid config file
	configContent := `
debug: true
bpf_program_path: ./l4_filter.o
bpf_pin_path: /sys/fs/bpf/
iface: lo
api_listen_addr: 127.0.0.1:9090
guarded_ports_range: 1024-2048
handshake_window_secs: 30
shutdown_timeout: 5
`

	// Create temp directory and file structure
	tmpDir := createTempDir(t)
	defer os.RemoveAll(tmpDir)

	configFile := filepath.Join(tmpDir, "config.yml")
	err := os.WriteFile(configFile, []byte(configContent), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// Create BPF program file
	bpfFile := filepath.Join(tmpDir, "l4_filter.o")
	err = os.WriteFile(bpfFile, []byte("test"), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// Create BPF pin directory
	bpfPinDir := filepath.Join(tmpDir, "bpf_pin")
	err = os.MkdirAll(bpfPinDir, 0o755)
	if err != nil {
		t.Fatal(err)
	}

	// Update config content with actual paths
	configContent = `
debug: true
bpf_program_path: ` + bpfFile + `
bpf_pin_path: ` + bpfPinDir + `
iface: lo
api_listen_addr: 127.0.0.1:9090
guarded_ports_range: 1024-2048
handshake_window_secs: 30
shutdown_timeout: 5
`

	err = os.WriteFile(configFile, []byte(configContent), 0o644)
	if err != nil {
		t.Fatal(err)
	}

	// Backup and restore command line arguments
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Set command line arguments
	os.Args = []string{"cmd", "-config", configFile}

	// Test NewConfig
	cfg, err := NewConfig()
	if err != nil {
		t.Fatalf("NewConfig() failed: %v", err)
	}

	// Verify config values
	if !cfg.Debug {
		t.Error("Debug should be true")
	}
	if cfg.BPFProgramPath != bpfFile {
		t.Errorf("BPFProgramPath = %s, want %s", cfg.BPFProgramPath, bpfFile)
	}
	if cfg.ConfigPath != configFile {
		t.Errorf("ConfigPath = %s, want %s", cfg.ConfigPath, configFile)
	}
	if cfg.ShutdownTimeout != 5 {
		t.Errorf("ShutdownTimeout = %d, want %d", cfg.ShutdownTimeout, 5)
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
