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
│   │   └── rest/v1/
│   │       └── `types.go`     # DTO REST API v1 (включая runtime_attached/runtime_iface)
│   │
│   ├── infrastructure/
│   │   ├── jwtauth/
│   │   │   └── `verifier.go`  # EdDSA JWT verifier + JWKS fetch/cache
│   │   ├── leshybpf/
│   │   │   ├── `attach_manager.go`     # Attach lifecycle
│   │   │   ├── `attach_tc.go`          # Загрузка/attach tc+bpf
│   │   │   ├── `filter_backend.go`     # Backend adapter для application/filter
│   │   │   ├── `runtime_settings_applier.go` # Динамическое применение iface/ports/window
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
│   │   │   ├── httpserver/
│   │   │   │   ├── `server.go`   # HTTP transport (runtime.Server)
│   │   │   │   └── `handlers.go`
│   │   │   ├── router/
│   │   │   │   └── `router.go`   # Root router (/api/v1, /api/healthz)
│   │   │   └── v1/
│   │   │       └── `api.go`      # HTTP handlers v1, auth middleware + mapping -> usecases
│   │   │
│   │   └── grpc/                 # roadmap: mirror/replace REST routes via gRPC
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
> gRPC-слой сохранен как roadmap: в дальнейшем текущие REST-сценарии будут продублированы/перенесены в gRPC transport.

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
3. В `settings` передаются runtime-параметры фильтра: `iface`, `guarded_ports_range`, `handshake_window_sec`.
4. `POST /api/v1/management/block` очищает разрешающие правила (`pending` и `active_flows`), созданные через `/allow`.
5. После успешного `POST` или `PATCH` приложение динамически поднимает/обновляет eBPF runtime.
6. `JWT` для `/allow`, `PATCH /management/settings` и `POST /management/block` проверяется по `JWKS` внешней системы (`EdDSA / Ed25519`).

### 1. Подготовка bootstrap-токена

1. Сгенерируйте криптографически стойкий токен (пример):
```bash
openssl rand -base64 48 | tr '+/' '-_' | tr -d '='
```
2. Запишите токен в конфиг приложения (`config.yml`):
```yaml
management_bootstrap_token: "REPLACE_WITH_RANDOM_TOKEN"
```

3. Сгенерируйте самоподписанные TLS-сертификаты, если нет готовых
```bash
openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
```

4. Запишите путь в конфиг приложения (`config.yml`):
```yaml
crt_path: ./server.crt
key_path: ./server.key
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

### 2.1 Доверие к TLS-сертификату JWKS (важно для стенда)

`leshy-controller` забирает JWKS через стандартный `net/http` клиент Go и проверяет TLS-цепочку по системному trust store хоста, где запущен контроллер.

Это значит:
1. `jwks_url` должен быть `https://...` с валидным сертификатом и корректным именем хоста (SAN/CN).
2. Самоподписанный сертификат без доверенной CA приведет к ошибке загрузки JWKS (`authorization unavailable` / `failed to save management settings`).
3. Для тестового стенда используйте один из вариантов:
   - выпустить сертификат от внутренней/публичной CA, которой доверяет ОС;
   - добавить вашу тестовую CA в системный trust store узла с `leshy-controller`;
   - для локального dev использовать `mkcert` и установить локальную CA в trust store.

Примечание: insecure-режим с отключением TLS-проверки в `leshy-controller` не предусмотрен.

### 3. Первичная конфигурация приложения (`/api/v1/management/settings`)

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
    "iface": "ens18",
    "handshake_window_sec": 600
  }'
```
Пример успешного ответа:
```json
{
  "message": "Management settings saved",
  "auth_configured": true,
  "runtime_attached": true,
  "runtime_iface": "ens18",
  "issuer": "https://auth.example.com",
  "audience": "leshy-controller",
  "jwks_url": "https://auth.example.com/.well-known/jwks.json",
  "required_scope": "allow:write",
  "guarded_ports_range": "3389-3390",
  "iface": "ens18",
  "handshake_window_sec": 600,
  "updated_at": "2026-02-11T12:00:00Z"
}
```

Успешный http-запрос в ответе получит статус 200.

### 4. Вызов `/allow` из внешней системы

1. Внешняя система выпускает JWT приватным ключом `Ed25519`.
2. Отправляет запрос:
```bash
curl -X POST "http://<host>:9090/api/v1/allow" \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.10","port":3389}'
```

### 5. Обновление настроек (`PATCH /api/v1/management/settings`)

Для изменения уже сохраненных настроек используйте `PATCH` и тот же access token, что используется для `/allow`:
```bash
curl -X PATCH "http://<host>:9090/api/v1/management/settings" \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "issuer": "https://auth.example.com",
    "audience": "leshy-controller",
    "jwks_url": "https://auth.example.com/.well-known/jwks.json",
    "required_scope": "allow:write",
    "guarded_ports_range": "3389-3395",
    "iface": "ens18",
    "handshake_window_sec": 900
  }'
```
Примечание: сейчас `PATCH` ожидает полный объект settings (не partial update).

### 6. Экстренная блокировка (`POST /api/v1/management/block`)

Ручка очищает все разрешения, ранее выданные через `/allow`:
- удаляет записи из `pending`;
- удаляет записи из `active_flows`.

Запрос:
```bash
curl -X POST "http://<host>:9090/api/v1/management/block" \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>"
```

Пример успешного ответа:
```json
{
  "message": "All allow rules were flushed",
  "pending_entries_removed": 3,
  "active_flows_removed": 2,
  "runtime_attached": true,
  "runtime_iface": "ens18"
}
```

### 7. Поведение после настройки

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

### 8. Пошаговый пример для stub-auth как подключить внешний auth-сервис

[GitHub Gist](https://gist.github.com/devalv/33998fbcf2d1ae3ba53c835340ba3614)

### 9. Сброс настроек

1. Остановите leshy-controller
2. Удалите локальную БД (файл)
3. Запустите leshy-controller
4. Выполните повторную настройку (`/api/v1/management/settings`)
