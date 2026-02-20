# leshy-controller

[![Go Report Card](https://goreportcard.com/badge/github.com/devalv/leshy-controller)](https://goreportcard.com/report/github.com/devalv/leshy-controller)
[![clang-format-check](https://github.com/devalv/leshy-controller/actions/workflows/clang-format.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/clang-format.yml)
[![Hadolint Dockerfile scan](https://github.com/devalv/leshy-controller/actions/workflows/hadolint-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/hadolint-scan.yml)
[![semgrep Security Scan](https://github.com/devalv/leshy-controller/actions/workflows/semgrep-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/semgrep-scan.yml)
[![Trivy CBPF builder scan](https://github.com/devalv/leshy-controller/actions/workflows/trivy-cbpf-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/trivy-cbpf-scan.yml)
[![Trivy Go Scan](https://github.com/devalv/leshy-controller/actions/workflows/trivy-go-scan.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/trivy-go-scan.yml)
[![tests-go](https://github.com/devalv/leshy-controller/actions/workflows/go-tests.yml/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/go-tests.yml)
[![coverage](./docs/badges/coverage.svg)](https://github.com/devalv/leshy-controller/actions/workflows/coverage-badge.yml)
[![Dependency Graph](https://github.com/devalv/leshy-controller/actions/workflows/dependabot/update-graph/badge.svg)](https://github.com/devalv/leshy-controller/actions/workflows/dependabot/update-graph)

"Контроллер "Леший"

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
│   └── controller/
│       └── `main.go`
│           # Точка входа
│           # - читает конфиг
│           # - настраивает контекст сигналов
│           # - вызывает bootstrap.New(cfg) и затем application.Run(ctx)
│
├── internal/
│   ├── application/
│   │   ├── filter/
│   │   │   ├── `port.go`      # Контракт backend для сценария allow/stats
│   │   │   ├── `service.go`   # UseCase для /allow
│   │   │   └── `stats.go`     # Модель расширенной статистики
│   │   └── management/
│   │       ├── `types.go`     # Настройки trust-контура + runtime status
│   │       ├── `port.go`      # Контракты usecase/repository/verifier/runtime applier
│   │       └── `service.go`   # Bootstrap + валидация settings + авторизация JWT
│   │
│   ├── bootstrap/
│   │   └── `bootstrap.go`     # Composition root + применение сохраненных settings при старте
│   │
│   ├── config/
│   │   ├── `config.go`        # Чтение yaml и runtime-валидация общих параметров
│   │   └── `config_test.go`
│   │
│   ├── contracts/
│   │   ├── rest/v1/
│   │   │   └── `types.go`                 # DTO REST API v1 (включая runtime_attached/runtime_iface)
│   │   └── grpc/v1/
│   │       ├── `leshy_controller_v1.pb.go`
│   │       └── `leshy_controller_v1_grpc.pb.go` # Сгенерированные контракты из docs/api/grpc/*.proto
│   │
│   ├── infrastructure/
│   │   ├── jwtauth/
│   │   │   └── `verifier.go`  # EdDSA JWT verifier + JWKS fetch/cache
│   │   ├── leshybpf/
│   │   │   ├── `attach_manager.go`     # Attach lifecycle
│   │   │   ├── `attach_tc.go`          # Загрузка/attach tc+bpf
│   │   │   ├── `filter_backend.go`     # Backend adapter для application/filter
│   │   │   ├── `runtime_settings_applier.go` # Динамическое применение iface/ports/handshake/inactive-timer
│   │   │   ├── `diagnostics_linux.go`  # Linux debug diagnostics
│   │   │   └── `*.go`                  # guarded ports, pending, stats, utils
│   │   └── sqlite/
│   │       ├── `db.go`                  # Open/prepare sqlite file
│   │       ├── `settings_repository.go` # Raw SQL репозиторий management settings
│   │       └── migrations/
│   │           ├── `embed.go`  # embed SQL миграций
│   │           ├── `runner.go` # применение миграций на старте
│   │           └── `sql/`
│   │               └── `0001_create_management_settings.sql`
│   │
│   ├── interfaces/
│   │   ├── grpc/
│   │   │   ├── server/
│   │   │   │   └── `server.go`   # gRPC transport (runtime.Server)
│   │   │   └── v1/
│   │   │       └── `api.go`      # gRPC handlers v1 + auth/validation/error mapping -> usecases
│   │   │
│   │   ├── rest/
│   │   │   ├── httpserver/
│   │   │   │   ├── `server.go`   # HTTP transport (runtime.Server)
│   │   │   │   └── `handlers.go`
│   │   │   ├── router/
│   │   │   │   └── `router.go`   # Root router (/api/v1, /api/healthz)
│   │   │   └── v1/
│   │   │       └── `api.go`      # HTTP handlers v1, auth middleware + mapping -> usecases
│   │   │
│   └── runtime/
│       ├── `app.go`          # Оркестратор жизненного цикла приложения
│       ├── `close_server.go` # Adapter для graceful close ресурсов
│       └── `server.go`       # Контракт транспорта Start/Stop/Name
│
├── devops/
│   └── ... (скрипты сборки)
│
├── docs/
│   ├── examples/
│   │   └── `basic.md`
│   │
│   ├── cbpf/
│   │   └── `cbpf-schema.drawio`
│   │
│   ├── plantuml/
│   │   ├── `c4-component.puml`
│   │   ├── `c4-containter.puml`
│   │   └── `c4-context.puml`
│   │
│   ├── api/
│   │   ├── grpc/
│   │   │   └── `leshy_controller_v1.proto` # gRPC-контракт, зеркалирующий HTTP API
│   │   └── swagger/
│   │
│   ├── badges/
│   │   └── `coverage.svg`
│   │
│   ├── `architecture.md`
│   │
│   └── `c4.md`
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
> API транспорт переключается через `api_server_mode`: `http` (REST) или `grpc` (protobuf контракт из `docs/api/grpc`).

## Вызовы консольных утилит

### bpftool
Используется в режиме отладки. Если отсутствует в системе - будет залогировано предупреждение. Необходима для расширенного анализа вывода bpf-программ.


### tc
Используется для расширенной аналитики планировщика пакетов ядра.

## x86/x64
Все тестирование и адаптация исключительно выполнялось для x64. На x86 с большой долей вероятности будут ошибки конвертации.

## Отладка
Отладка, во многом, опирается на bpftool. Пример сборки из исходных текстов - https://gist.github.com/devalv/0d4af62eca14b1ea91b8f7c2c6f3f163

## Подключение внешней системы

Текущая схема:
1. `POST /api/v1/management/settings` доступен только в bootstrap-режиме (заголовок `X-Bootstrap-Token`).
2. `PATCH /api/v1/management/settings` доступен только после первичной конфигурации и авторизуется тем же `Bearer` access token, что и `/allow`.
3. В `settings` передаются runtime-параметры фильтра: `iface`, `guarded_ports_range`, `handshake_window_sec`, `inactive_timer_sec`.
4. `POST /api/v1/management/block` очищает разрешающие правила (`pending` и `active_flows`), созданные через `/allow`.
5. После успешного `POST` или `PATCH` приложение динамически поднимает/обновляет eBPF runtime.
6. `JWT` для `/allow`, `PATCH /management/settings` и `POST /management/block` проверяется по `JWKS` внешней системы (`EdDSA / Ed25519`).

Примечание: insecure-режим с отключением TLS-проверки в `leshy-controller` не предусмотрен.

[Дополнительные примеры](./docs/examples/basic.md)
[openAPI](./docs/api/swagger/swagger.json)
[gRPC proto](./docs/api/grpc/leshy_controller_v1.proto)

Генерация Go-контрактов из protobuf:
`make grpc`

## Режим API сервера

1. `api_server_mode: http`:
   - запускается REST API на `api_listen_addr`;
   - доступны `/api/healthz` и `/api/v1/*`.
2. `api_server_mode: grpc`:
   - запускается gRPC сервер на `api_listen_addr`;
   - доступны сервисы `HealthService`, `FilterService`, `ManagementService` из `docs/api/grpc/leshy_controller_v1.proto`.

## Сброс настроек

1. Остановите leshy-controller
2. Удалите локальную БД (файл)
3. Запустите leshy-controller

## Поведение после настройки (http)

1. После первого успешного `POST /api/v1/management/settings` bootstrap-endpoint блокируется (`409 management settings are locked`), включая сценарий после перезапуска приложения.
2. Для последующих изменений используется `PATCH /api/v1/management/settings` (Bearer JWT).
3. После перезапуска приложение читает сохранённые settings из SQLite и повторно применяет их в runtime (attach выполняется автоматически при наличии сохраненных настроек).
4. Для ротации ключей публикуйте новый ключ в JWKS с новым `kid`, затем выпускайте новые JWT с этим `kid`.
5. Если `management_bootstrap_token` не задан в конфиге, `POST /api/v1/management/settings` вернёт `503`.
6. Если settings еще не заданы, runtime не подключен:
   - `POST /api/v1/allow` вернет `503 filter is not configured`
   - `GET /api/v1/stats` вернет `503 filter is not configured`
   - `GET /api/healthz` вернет JSON с `runtime_attached: false`
7. Runtime-статус дублируется в:
   - `GET /api/healthz` (`runtime_attached`)
   - `GET /api/v1/management/settings`
   - `POST /api/v1/management/settings`
   - `PATCH /api/v1/management/settings`
   - `POST /api/v1/management/block`
8. Типовые ответы для `PATCH /api/v1/management/settings`:
   - `200` при успешном обновлении;
   - `400` при ошибках валидации тела запроса;
   - `401` при невалидном или отсутствующем `Authorization: Bearer ...`;
   - `409` если настройки еще не были заданы;
   - `503` если авторизация временно недоступна (`authorization unavailable`).
9. Типовые ответы для `POST /api/v1/management/block`:
   - `200` при успешной очистке разрешающих правил;
   - `401` при невалидном или отсутствующем `Authorization: Bearer ...`;
   - `409` если настройки еще не были заданы;
   - `503` если авторизация или filter-runtime недоступны;
   - `500` при внутренней ошибке очистки.

## Поведение после настройки (grpc)

1. После первого успешного `ManagementService/CreateSettings` bootstrap-вызов блокируется и повторный вызов вернет `FailedPrecondition` (`management settings are locked`), включая сценарий после перезапуска приложения.
2. Для последующих изменений используется `ManagementService/UpdateSettings` (Bearer JWT в metadata `authorization`).
3. После перезапуска приложение читает сохранённые settings из SQLite и повторно применяет их в runtime (attach выполняется автоматически при наличии сохраненных настроек).
4. Для ротации ключей публикуйте новый ключ в JWKS с новым `kid`, затем выпускайте новые JWT с этим `kid`.
5. Если `management_bootstrap_token` не задан в конфиге, `ManagementService/CreateSettings` вернёт `Unavailable`.
6. Если settings еще не заданы, runtime не подключен:
   - `FilterService/Allow` вернет `Unavailable` (`Authorization is unavailable`);
   - `FilterService/Stats` вернет `Unavailable` (`Authorization is unavailable`);
   - `HealthService/Health` вернет `runtime_attached: false`.
7. Runtime-статус дублируется в:
   - `HealthService/Health` (`runtime_attached`);
   - `ManagementService/GetSettings`;
   - `ManagementService/CreateSettings`;
   - `ManagementService/UpdateSettings`;
   - `ManagementService/Block`.
8. Типовые ответы для `ManagementService/UpdateSettings`:
   - `OK` при успешном обновлении;
   - `InvalidArgument` при ошибках валидации запроса;
   - `Unauthenticated` при невалидном или отсутствующем `authorization: Bearer ...`;
   - `FailedPrecondition` если настройки еще не были заданы;
   - `Unavailable` если авторизация временно недоступна (`authorization unavailable`).
9. Типовые ответы для `ManagementService/Block`:
   - `OK` при успешной очистке разрешающих правил;
   - `Unauthenticated` при невалидном или отсутствующем `authorization: Bearer ...`;
   - `FailedPrecondition` если настройки еще не были заданы;
   - `Unavailable` если авторизация или filter-runtime недоступны;
   - `Internal` при внутренней ошибке очистки.

## Дополнительная документация
[architecture.md](./docs/architecture.md)
