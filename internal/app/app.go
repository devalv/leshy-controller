package app

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/devalv/leshy-controller/internal/config"
	"github.com/devalv/leshy-controller/internal/infrastructure"
	v1 "github.com/devalv/leshy-controller/internal/interfaces/rest/v1"
	"github.com/rs/zerolog/log"
)

type Application struct {
	cfg *config.Config
}

func NewApplication(cfg *config.Config) *Application {
	app := &Application{cfg: cfg}

	return app
}

func (app *Application) Start(ctx context.Context) {
	log.Debug().Msg("Starting the application")

	// Снимаем ограничения на ресурсы eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal().Err(err).Msg("failed to remove memlock limit")
	}

	// Создаем директорию для pinning если не существует
	if err := os.MkdirAll(app.cfg.BPFPinPath, 0o755); err != nil { //nolint
		log.Fatal().Err(err).Msg("failed to create BPF pin directory")
	}

	// Получаем интерфейс из переменной окружения или используем значение по умолчанию
	log.Info().Msgf("using network interface: %s", app.cfg.Iface)

	// Загружаем и прикрепляем BPF программу (она создаст и закрепит карты)
	// ВАЖНО: получаем карты из коллекции, чтобы использовать те же карты, что и программа
	var pendingMap, guardedPortsMap, statsMap, activeFlowsMap *ebpf.Map
	if err := infrastructure.AttachBPFWithTC(app.cfg.Iface, app.cfg.BPFPinPath, app.cfg.BPFProgramPath, &pendingMap, &guardedPortsMap, &statsMap, &activeFlowsMap); err != nil { //nolint:lll
		log.Fatal().Err(err).Msg("failed to attach BPF program")
	}

	// Проверяем, что карты получены.
	if pendingMap == nil || guardedPortsMap == nil || statsMap == nil || activeFlowsMap == nil {
		log.Fatal().Msg("failed to get maps from BPF collection")
	}

	log.Debug().Msg("maps obtained from BPF collection:")
	log.Debug().Msgf("  pending map file descriptor: %d", pendingMap.FD())
	log.Debug().Msgf("  guarded ports map file descriptor: %d", guardedPortsMap.FD())
	log.Debug().Msgf("  stats map file descriptor: %d", statsMap.FD())
	log.Debug().Msgf("  active flows map file descriptor: %d", activeFlowsMap.FD())

	// Initialize guarded ports from environment
	infrastructure.InitializeGuardedPorts(app.cfg.GuardedPortsRange, guardedPortsMap)

	// Создаем HTTP обработчики
	mux := v1.SetupHTTPHandlers(time.Duration(app.cfg.HandshakeWindowSecs)*time.Second, pendingMap, guardedPortsMap, statsMap) //nolint:lll

	log.Debug().Msgf("listening on %s", app.cfg.APIListenAddr)
	log.Debug().Msgf("allow endpoint: POST http://%s/allow with JSON body", app.cfg.APIListenAddr)
	log.Debug().Msgf("deny endpoint: POST http://%s/deny with JSON body", app.cfg.APIListenAddr) // TODO: проверить
	log.Debug().Msgf("handshake window: %d secs", app.cfg.HandshakeWindowSecs)
	log.Debug().Msgf("guarded ports: %v", infrastructure.GetGuardedPorts(guardedPortsMap))
	err := http.ListenAndServe(app.cfg.APIListenAddr, mux) // #nosec G114
	if err != nil {
		log.Fatal().Err(err).Msg("HTTP server start failed")
	}

	app.Stop(ctx)
}

func (app *Application) Stop(ctx context.Context) {
	log.Debug().Msg("Application stopped")
	os.Exit(0)
}
