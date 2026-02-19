# Архитектура решения

`leshy-controller` построен по принципам чистой архитектуры:
- `internal/application/*` содержит use-case слой (`filter`, `management`);
- `internal/infrastructure/*` содержит адаптеры (eBPF, sqlite, JWKS/JWT);
- `internal/interfaces/*` содержит transport-слой (`rest`, `grpc`);
- `internal/bootstrap` связывает зависимости и запускает приложение.

## API транспорт

Режим запуска API выбирается через `api_server_mode` в конфигурации:
- `http` — поднимается REST API (`/api/healthz`, `/api/v1/*`);
- `grpc` — поднимается gRPC API по контракту `docs/api/grpc/leshy_controller_v1.proto`.

Оба режима используют один и тот же `api_listen_addr` и общий application layer.

## C4 документация

- C4-описание системы: [`docs/c4.md`](./c4.md)
- Экспорт в PlantUML:
  - [`docs/plantuml/c4-context.puml`](./plantuml/c4-context.puml)
  - [`docs/plantuml/c4-container.puml`](./plantuml/c4-container.puml)
  - [`docs/plantuml/c4-component.puml`](./plantuml/c4-component.puml)
