package bootstrap

import (
	"context"
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

func New(ctx context.Context, cfg *config.Config) (*runtime.Application, error) {
	const (
		executablePerm = 0o755
		attachTimeout  = 30 * time.Second
	)

	// eBPF prep
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	if err := os.MkdirAll(cfg.BPFPinPath, executablePerm); err != nil {
		return nil, fmt.Errorf("create BPF pin directory: %w", err)
	}

	// attach BPF + maps (с отдельным таймаутом на bootstrap-attach)
	attachCtx, cancel := context.WithTimeout(ctx, attachTimeout)
	defer cancel()

	var pendingMap, guardedPortsMap, statsMap, activeFlowsMap *ebpf.Map
	mgr, err := leshybpf.NewManagerAndAttach(
		attachCtx,
		cfg.Iface,
		cfg.BPFPinPath,
		cfg.BPFProgramPath,
		leshybpf.AttachOptions{Debug: cfg.Debug},
		&pendingMap, &guardedPortsMap, &statsMap, &activeFlowsMap,
	)
	if err != nil {
		return nil, fmt.Errorf("attach BPF program: %w", err)
	}

	if pendingMap == nil || guardedPortsMap == nil || statsMap == nil || activeFlowsMap == nil {
		return nil, errors.New("failed to get maps from BPF collection (nil)")
	}

	if err := leshybpf.InitializeGuardedPorts(cfg.GuardedPortsRange, guardedPortsMap); err != nil {
		return nil, fmt.Errorf("initialize guarded ports: %w", err)
	}

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

	// closer server: держит mgr живым и закрывает при shutdown
	closer := runtime.NewCloserServer("leshybpf", func(stopCtx context.Context) error {
		_ = stopCtx // сейчас mgr.Close() контекст не использует; оставляем на будущее

		return mgr.Close()
	})

	application := runtime.NewApplication(
		runtime.Options{
			ShutdownTimeout: time.Duration(cfg.ShutdownTimeout) * time.Second,
		},
		httpSrv,
		closer,
	)

	return application, nil
}
