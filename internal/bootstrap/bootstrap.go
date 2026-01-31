package bootstrap

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/devalv/leshy-controller/internal/application/filter"
	"github.com/devalv/leshy-controller/internal/config"
	leshybpf "github.com/devalv/leshy-controller/internal/infrastructure/leshybpf"
	httpserver "github.com/devalv/leshy-controller/internal/interfaces/rest/httpserver"
	restrouter "github.com/devalv/leshy-controller/internal/interfaces/rest/router"
	v1 "github.com/devalv/leshy-controller/internal/interfaces/rest/v1"
	"github.com/devalv/leshy-controller/internal/runtime"
)

func New(cfg *config.Config) (*runtime.Application, error) {
	// eBPF prep
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	if err := os.MkdirAll(cfg.BPFPinPath, 0o755); err != nil { //nolint
		return nil, fmt.Errorf("create BPF pin directory: %w", err)
	}

	// attach BPF + maps
	var pendingMap, guardedPortsMap, statsMap, activeFlowsMap *ebpf.Map
	if err := leshybpf.AttachBPFWithTCWithOptions(
		cfg.Iface,
		cfg.BPFPinPath,
		cfg.BPFProgramPath,
		leshybpf.AttachOptions{Debug: cfg.Debug},
		&pendingMap,
		&guardedPortsMap,
		&statsMap,
		&activeFlowsMap,
	); err != nil {
		return nil, fmt.Errorf("attach BPF program: %w", err)
	}
	if pendingMap == nil || guardedPortsMap == nil || statsMap == nil || activeFlowsMap == nil {
		return nil, errors.New("failed to get maps from BPF collection (nil)")
	}

	leshybpf.InitializeGuardedPorts(cfg.GuardedPortsRange, guardedPortsMap)

	// --- Usecase + Backend wiring ---
	backend := leshybpf.NewFilterBackend(pendingMap, guardedPortsMap, statsMap)

	filterSvc := filter.New(backend, filter.Options{
		Window: time.Duration(cfg.HandshakeWindowSecs) * time.Second,
		Debug:  cfg.Debug,
	})

	// --- HTTP handlers (v1) ---
	v1mux := http.NewServeMux()
	v1.Register(v1mux, v1.Deps{
		Filter: filterSvc,
	})

	// --- REST router ---
	root := restrouter.New(restrouter.Options{
		HealthPath: "/api/healthz",
	}, map[string]http.Handler{
		"/api/v1/": v1mux,
	})

	// http server
	httpSrv := httpserver.New(cfg.APIListenAddr, root)

	application := runtime.NewApplication(
		runtime.Options{
			ShutdownTimeout: time.Duration(cfg.ShutdownTimeout) * time.Second,
		},
		httpSrv,
	)

	return application, nil
}
