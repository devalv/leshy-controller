# leshy-controller

[![clang-format-check](https://github.com/devalv/leshy-controller/actions/workflows/clang-format.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/clang-format.yml)
[![Hadolint Dockerfile scan](https://github.com/devalv/leshy-controller/actions/workflows/hadolint-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/hadolint-scan.yml)
[![semgrep C Code Security Scan](https://github.com/devalv/leshy-controller/actions/workflows/semgrep-cpbf-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/semgrep-cpbf-scan.yml)
[![Trivy CBPF builder scan](https://github.com/devalv/leshy-controller/actions/workflows/trivy-cbpf-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/trivy-cbpf-scan.yml)
[![tests-go](https://github.com/devalv/leshy-controller/actions/workflows/go-tests.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/go-tests.yml)

## Компоненты

### bpf-фильтр

См. [README](./cbpf/README.md)

## Структура репозитория

```markdown
│
├── cbpf/
│   ├── filter/
│   │   └── `*.c`
│   │
│   ├── tests/
│   │   └── `*.c`
│   │
│   ├── Makefile
│   │
│   └── README.md
│
├── cmd/
│   └── leshy-controller/
│       └── `main.go`
│           # Точка входа
│           # - читает конфиг
│           # - настраивает контекст сигналов
│           # - вызывает bootstrap.New(cfg) и затем application.Run(ctx)
│
├── internal/
│   ├── runtime/
│   │   ├── `app.go`
│   │   │   # Оркестратор жизненного цикла.
│   │   │   # - принимает набор Server (транспортов)
│   │   │   # - управляет запуском/остановкой (graceful shutdown)
│   │   │
│   │   ├── `close_server.go`
│   │   │   # "виртуальный" Server для освобождения ресурсов на shutdown
│   │   │
│   │   └── `server.go`
│   │       # Порт для транспорта (primary adapter).
│   │       # Интерфейс абстрактного сервера: Start/Stop/Name
│   │
│   ├── bootstrap/
│   │   └── `bootstrap.go`
│   │       # Composition root / "сборка" приложения.
│   │       # Единственное место, где "склеиваются" зависимости:
│   │       # - чтение cfg значений и преобразование в Options
│   │       # - инициализация инфраструктуры (rlimit, pin dir, attach eBPF)
│   │       # - создание backend-адаптеров (eBPF backend)
│   │       # - создание usecase сервисов (application layer)
│   │       # - сборка HTTP mux (версионирование /api/v1) и создание серверов
│   │       # Возвращает `*app.Application` (оркестратор) готовый к `Run(ctx)`
│   │
│   ├── config/
│   │   ├── `config.go`
│   │   │   # Структура Config и чтение yaml/env.
│   │   │   # Важно: config — не часть "чистой" архитектуры, это внешний ввод.
│   │   │   # Его используют main/bootstrap, но не usecase и не интерфейсные адаптеры.
│   │   └── `config_test.go`
│   │
│   ├── application/  # usecases
│   │   └── filter/
│   │       ├── `service.go`
│   │       │   # Application / Usecase слой.
│   │       │   # Содержит сценарии (Allow, Stats) и правила (guarded-only, window).
│   │       │   # Зависит только от порта Backend (интерфейса), а не от eBPF.
│   │       │
│   │       ├── `stats.go`
│   │       │   # Расширенная статистика работы
│   │       │
│   │       └── `port.go`
│   │           # Port (secondary port) для инфраструктуры.
│   │           # Контракт, который должен реализовать backend (eBPF/мок/иная реализация).
│   │
│   ├── interfaces/
│   │   ├── rest/
│   │   │   ├── httpserver/
│   │   │   │   ├── `server.go`
│   │   │   │   │   # HTTP transport adapter.
│   │   │   │   │   # Реализация app.Server через net/http.Server + Shutdown.
│   │   │   │   │   # Не содержит бизнес-логики: только старт/стоп сервера.
│   │   │   │   └── `handlers.go`
│   │   │   │       # Вспомогательные дефолтные хендлеры (например NotFound).
│   │   │   │
│   │   │   ├── router/
│   │   │   │   └── `router.go`
│   │   │   │       # Система роутинга хендлеров
│   │   │   │
│   │   │   └── v1/
│   │   │       ├── `api.go`
│   │   │       │   # HTTP adapter уровня v1.
│   │   │       │   # - парсит HTTP/JSON
│   │   │       │   # - вызывает usecase (application/filter.UseCase)
│   │   │       │   # - возвращает HTTP/JSON
│   │   │       │   # НЕ знает про ebpf.Map и НЕ вызывает infrastructure напрямую.
│   │   │
│   │   └── grpc/ (аналогичный слою rest)
│   │       ├── server/
│   │       │   # gRPC transport adapter (реализация app.Server)
│   │       └── v1/
│   │           # gRPC handlers v1: вызывают те же usecase (application/filter)
│   │
│   ├── infrastructure/
│   │   ├── leshybpf/
│   │   │   ├── `attach_manager.go`
│   │   │   │   # управление жизненным циклом attach_tc
│   │   │   │
│   │   │   ├── `attach_tc.go`
│   │   │   │   # Загрузка BPF-коллекции, pinning карт/программы и attach к TC (ingress).
│   │   │   │   # Это “операционный” код инфраструктуры: взаимодействие с ОС, tc, pinned paths.
│   │   │   │
│   │   │   ├── `exec.go`
│   │   │   │   # Обёртки для запуска консольных утилит (tc, bpftool).
│   │   │   │
│   │   │   ├── `diagnostics_linux.go`
│   │   │   │   # Расширенная диагностика (bpftool/tc): поиск program map_ids, сравнение с pinned map IDs,
│   │   │   │   # проверка pinned путей на FS. Запускается только в debug-режиме.
│   │   │   │   # Linux-only (build tag).
│   │   │   │
│   │   │   ├── `pending.go`
│   │   │   │   # Запись pending-авторизаций в eBPF map.
│   │   │   │   # Содержит работу с байтовыми ключами и прямой syscall bpf() (SYS_BPF),
│   │   │   │   # чтобы гарантировать network byte order ключей.
│   │   │   │
│   │   │   ├── `guarded_ports.go`
│   │   │   │   # Управление “guarded ports” картой: парс диапазона портов, запись/очистка,
│   │   │   │   # проверка, что порт guarded, чтение списка портов.
│   │   │   │
│   │   │   ├── `stats.go`
│   │   │   │   # Чтение статистики из stats map и преобразование в типизированные счетчики
│   │   │   │   # application/filter.Counters (без map[string]interface{}).
│   │   │   │
│   │   │   ├── `filter_backend.go`
│   │   │   │   # Реализация application/filter.Backend на eBPF maps.
│   │   │   │   # Здесь “адаптер” инфраструктуры использует функции этого же пакета:
│   │   │   │   # IsPortGuarded / InsertPendingSrcPort / readCountersFromStatsMap и т.д.
│   │   │   │
│   │   │   ├── `constants.go`
│   │   │   │   # Имена pinned объектов (карты/программа) и константы, связанные с BPF.
│   │   │   │
│   │   │   ├── `byteorder.go`
│   │   │   │   # Преобразование портов host<->network byte order.
│   │   │   │
│   │   │   ├── `ipport_key.go`
│   │   │   │   # Структура ключа eBPF карты (IpPortKey). Это инфраструктурная деталь, не API/домен.
│   │   │   │
│   │   │   └── `collection.go`
│   │   │       # Хранение ссылки на загруженную BPF коллекцию, чтобы она не была закрыта.
│   │   │       # Позже можно заменить на отдельный Manager (вместо глобальной переменной).
│   │   │
│   │   └── ... (прочая инфраструктура, не связанная с eBPF)
│   │
│   ├── contracts/
│   │   └── rest/
│   │       └── v1/
│   │           └── `types.go`
│   │           # DTO/контракты API (AllowRequest/AllowResponse/StatsResponse).
│   │           # Это НЕ domain: это формат внешнего обмена (HTTP/gRPC).
│   │
├── devops/
│   └── ... (скрипты сборки)
│
├── docs/
│   ├── examples/
│   │   ├── `basic.md`
│   │   ├── advanced/
│   ├── cbpf/
│   ├── `architecture.md`
│   └── api/
│
├── .pre-commit-config.yaml    # Pre-commit хуки
├── .clang-format              # Форматирование C
├── .golangci.yaml             # Go линтер
├── Makefile                   # Основной Makefile
├── go.mod                     # Go модули
├── go.sum
├── LICENSE
└── README.md
```

### Комментарии

> **infrastructure/leshybpf** — это *конкретный secondary adapter* (инфраструктурный драйвер) для Linux/eBPF/TC.
> Usecase-слой (`internal/application/filter`) **не знает** про `*ebpf.Map`, `tc`, `bpftool` и syscalls: он общается с инфраструктурой только через порт `filter.Backend`.
> Внутри `leshybpf` собрана вся “железная” логика: attach/pin, работа с картами, byte order, и опциональная диагностика (только в debug).

### Вызовы консольных утилит

#### bpftool
Используется в режиме отладки. Если отсутствует в системе - будет залогировано предупреждение. Необходима для расширенного анализа вывода bpf-программ.


#### tc
Используется для расширенной аналитики планировщика пакетов ядра.
