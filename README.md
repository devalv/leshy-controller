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
│   ├── application/
│   │   ├── filter/
│   │   │   ├── `port.go`      # Контракт backend для сценария allow/stats
│   │   │   ├── `service.go`   # UseCase для /allow
│   │   │   └── `stats.go`     # Модель расширенной статистики
│   │   └── management/
│   │       ├── `types.go`     # Настройки trust-контура (issuer/audience/jwks/scope)
│   │       ├── `port.go`      # Контракты usecase/repository/verifier
│   │       └── `service.go`   # Валидация settings + bootstrap + авторизация JWT
│   │
│   ├── bootstrap/
│   │   └── `bootstrap.go`     # Composition root (wire всех зависимостей)
│   │
│   ├── config/
│   │   ├── `config.go`        # Чтение yaml и runtime-валидация
│   │   └── `config_test.go`
│   │
│   ├── contracts/
│   │   └── rest/v1/
│   │       └── `types.go`     # DTO REST API v1
│   │
│   ├── infrastructure/
│   │   ├── jwtauth/
│   │   │   └── `verifier.go`  # EdDSA JWT verifier + JWKS fetch/cache
│   │   ├── leshybpf/
│   │   │   ├── `attach_manager.go`     # Attach lifecycle
│   │   │   ├── `attach_tc.go`          # Загрузка/attach tc+bpf
│   │   │   ├── `filter_backend.go`     # Backend adapter для application/filter
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
│   │   ├── rest/
│   │       ├── httpserver/
│   │       │   ├── `server.go`   # HTTP transport (runtime.Server)
│   │       │   └── `handlers.go`
│   │       ├── router/
│   │       │   └── `router.go`   # Root router (/api/v1, /api/healthz)
│   │       └── v1/
│   │           └── `api.go`      # HTTP handlers v1, mapping -> usecases
│   │   └── grpc/                 # roadmap: mirror/replace REST routes via gRPC
│   │       ├── server/           # gRPC transport adapter (runtime.Server)
│   │       └── v1/               # gRPC handlers v1 (те же usecases)
│   │
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

#### x86/x64
Все тестирование и адаптация исключительно выполнялось для x64. На x86 с большой долей вероятности будут ошибки конвертации.

## Отладка
Отладка, во многом, опирается на bpftool. Пример сборки из исходных текстов - https://gist.github.com/devalv/0d4af62eca14b1ea91b8f7c2c6f3f163

## Подключение внешней системы

Текущая схема:
1. `POST /api/v1/management/settings` доступен только в bootstrap-режиме (заголовок `X-Bootstrap-Token`).
2. После сохранения настроек приложение авторизует `POST /api/v1/allow` только по JWT (`Authorization: Bearer ...`).
3. JWT проверяется по `JWKS` внешней системы (`EdDSA / Ed25519`).

### 1. Подготовка bootstrap-токена

1. Сгенерируйте криптографически стойкий токен (пример):
```bash
openssl rand -base64 48 | tr '+/' '-_' | tr -d '='
```
2. Запишите токен в конфиг приложения (`config.yml`):
```yaml
management_bootstrap_token: "REPLACE_WITH_RANDOM_TOKEN"
```
3. Защитите файл конфига правами доступа только для пользователя сервиса.
4. Запустите приложение.

### 2. Что должна сделать внешняя система

1. Сгенерировать пару ключей `Ed25519` (приватный ключ хранится только во внешней системе).
2. Поднять HTTPS endpoint с `JWKS` (публичные ключи), например:
```json
{
  "keys": [
    {
      "kty": "OKP",
      "crv": "Ed25519",
      "kid": "kid-2026-01",
      "x": "BASE64URL_PUBLIC_KEY"
    }
  ]
}
```
3. Определить постоянные значения `issuer`, `audience`, `required_scope` для вашей интеграции.
4. Реализовать выдачу короткоживущих JWT (рекомендуемо 5-15 минут) с header `kid` и claims:
`iss`, `aud`, `exp`, `nbf`, `iat`, `scope` (должен содержать `required_scope`), желательно `jti`.

### 3. Первичная конфигурация приложения (`/management/settings`)

Выполнить единоразовую настройку:
```bash
curl -X POST "http://<host>:9090/api/v1/management/settings" \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: REPLACE_WITH_RANDOM_TOKEN" \
  -d '{
    "issuer": "https://auth.example.com",
    "audience": "leshy-controller",
    "jwks_url": "https://auth.example.com/.well-known/jwks.json",
    "required_scope": "allow:write",
    "guarded_ports_range": "3389-3390",
    "iface": "ens18"
  }'
```

### 4. Вызов `/allow` из внешней системы

1. Внешняя система выпускает JWT приватным ключом `Ed25519`.
2. Отправляет запрос:
```bash
curl -X POST "http://<host>:9090/api/v1/allow" \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.10","port":3389}'
```

### 5. Поведение после настройки

1. После первого успешного `POST /management/settings` endpoint блокируется (`409 management settings are locked`), включая сценарий после перезапуска приложения.
2. После перезапуска приложение читает сохранённые настройки из SQLite и продолжает проверять JWT по ним.
3. Для ротации ключей публикуйте новый ключ в JWKS с новым `kid`, затем выпускайте новые JWT с этим `kid`.
4. Если `management_bootstrap_token` не задан в конфиге, `POST /management/settings` вернёт `503`.
