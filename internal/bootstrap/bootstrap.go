package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"google.golang.org/grpc"

	"github.com/devalv/leshy-controller/internal/application/filter"
	"github.com/devalv/leshy-controller/internal/application/management"
	"github.com/devalv/leshy-controller/internal/config"
	"github.com/devalv/leshy-controller/internal/infrastructure/jwtauth"
	leshybpf "github.com/devalv/leshy-controller/internal/infrastructure/leshybpf"
	sqliteinfra "github.com/devalv/leshy-controller/internal/infrastructure/sqlite"
	sqlitemigrations "github.com/devalv/leshy-controller/internal/infrastructure/sqlite/migrations"
	grpcserver "github.com/devalv/leshy-controller/internal/interfaces/grpc/server"
	grpcv1 "github.com/devalv/leshy-controller/internal/interfaces/grpc/v1"
	httpserver "github.com/devalv/leshy-controller/internal/interfaces/rest/httpserver"
	restrouter "github.com/devalv/leshy-controller/internal/interfaces/rest/router"
	v1 "github.com/devalv/leshy-controller/internal/interfaces/rest/v1"
	"github.com/devalv/leshy-controller/internal/runtime"
)

func New(ctx context.Context, cfg *config.Config) (*runtime.Application, error) {
	const (
		executablePerm = 0o755
	)

	// eBPF prep
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	if err := os.MkdirAll(cfg.BPFPinPath, executablePerm); err != nil {
		return nil, fmt.Errorf("create BPF pin directory: %w", err)
	}

	filterSvc := filter.New(nil, filter.Options{
		Debug: cfg.Debug,
	})
	settingsDB, err := sqliteinfra.Open(ctx, cfg.SettingsDBPath)
	if err != nil {
		return nil, fmt.Errorf("open settings db: %w", err)
	}

	migrationRunner, err := sqlitemigrations.NewEmbeddedRunner(settingsDB)
	if err != nil {
		_ = settingsDB.Close()

		return nil, fmt.Errorf("initialize sqlite migrations runner: %w", err)
	}

	if err := migrationRunner.Up(ctx); err != nil {
		_ = settingsDB.Close()

		return nil, fmt.Errorf("apply sqlite migrations: %w", err)
	}

	managementRepo, err := sqliteinfra.NewManagementSettingsRepository(settingsDB)
	if err != nil {
		_ = settingsDB.Close()

		return nil, fmt.Errorf("initialize management settings repository: %w", err)
	}
	runtimeSettingsApplier := leshybpf.NewRuntimeSettingsApplier(
		filterSvc,
		leshybpf.RuntimeSettingsApplierOptions{
			BPFPinPath:     cfg.BPFPinPath,
			BPFProgramPath: cfg.BPFProgramPath,
			Debug:          cfg.Debug,
		},
	)

	storedSettings, err := managementRepo.LoadSettings(ctx)
	if err != nil && !errors.Is(err, management.ErrSettingsNotFound) {
		_ = runtimeSettingsApplier.Close()
		_ = settingsDB.Close()

		return nil, fmt.Errorf("load management settings: %w", err)
	}
	if err == nil {
		if applyErr := runtimeSettingsApplier.Apply(ctx, storedSettings.Settings); applyErr != nil {
			_ = runtimeSettingsApplier.Close()
			_ = settingsDB.Close()

			return nil, fmt.Errorf("apply stored runtime management settings: %w", applyErr)
		}
	}

	managementVerifier := jwtauth.NewVerifier(jwtauth.VerifierOptions{})
	managementSvc := management.New(managementRepo, managementVerifier, management.Options{
		BootstrapToken: cfg.ManagementBootstrapToken,
		RuntimeApplier: runtimeSettingsApplier,
	})

	var apiServer runtime.Server
	switch cfg.APIServerMode {
	case config.APIServerModeHTTP:
		// --- HTTP handlers (v1) ---
		v1mux := http.NewServeMux()
		v1.Register(v1mux, v1.Deps{
			Filter:     filterSvc,
			Management: managementSvc,
		})

		// --- REST router ---
		root := restrouter.New(restrouter.Options{
			HealthPath:    "/api/healthz",
			HealthHandler: makeHealthHandler(managementSvc),
		}, map[string]http.Handler{
			"/api/v1/": v1mux,
		})

		apiServer = httpserver.New(cfg.APIListenAddr, cfg.CrtPath, cfg.KeyPath, root)
	case config.APIServerModeGRPC:
		apiServer = grpcserver.New(
			cfg.APIListenAddr,
			cfg.CrtPath,
			cfg.KeyPath,
			func(server *grpc.Server) {
				grpcv1.Register(server, grpcv1.Deps{
					Filter:     filterSvc,
					Management: managementSvc,
				})
			},
		)
	default:
		_ = runtimeSettingsApplier.Close()
		_ = settingsDB.Close()

		return nil, fmt.Errorf("unsupported api_server_mode: %s", cfg.APIServerMode)
	}

	// closer server: держит runtime-applier живым и закрывает при shutdown
	closer := runtime.NewCloserServer("leshybpf", func(stopCtx context.Context) error {
		_ = stopCtx // close сигнатура оставлена контекстной для единообразия runtime.Server.

		return runtimeSettingsApplier.Close()
	})
	managementDBCloser := runtime.NewCloserServer("managementdb", func(stopCtx context.Context) error {
		_ = stopCtx // close сигнатура оставлена контекстной для единообразия runtime.Server.

		return managementRepo.Close()
	})

	application := runtime.NewApplication(
		runtime.Options{
			ShutdownTimeout: time.Duration(cfg.ShutdownTimeoutSec) * time.Second,
		},
		apiServer,
		closer,
		managementDBCloser,
	)

	return application, nil
}

func makeHealthHandler(managementUseCase management.UseCase) http.Handler {
	type healthResponse struct {
		Status          string `json:"status"`
		RuntimeAttached bool   `json:"runtime_attached"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runtimeStatus := management.RuntimeStatus{}
		if managementUseCase != nil {
			runtimeStatus = managementUseCase.RuntimeStatus(r.Context())
		}

		response := healthResponse{
			Status:          "ok",
			RuntimeAttached: runtimeStatus.Attached,
		}

		payload, err := json.Marshal(response)
		if err != nil {
			http.Error(w, "failed to encode health response", http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	})
}
