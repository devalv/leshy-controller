# Примеры

## 1. Подготовка bootstrap-токена

1. Сгенерируйте криптографически стойкий токен:
```bash
openssl rand -base64 48 | tr '+/' '-_' | tr -d '='
```
2. Сгенерируйте TLS-сертификаты (если нет готовых):
```bash
openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 365 -out server.crt
```
3. Запишите значения в `config.yml`:
```yaml
management_bootstrap_token: "REPLACE_WITH_RANDOM_TOKEN"
api_listen_addr: 0.0.0.0:9090
api_server_mode: http # или grpc
crt_path: ./server.crt
key_path: ./server.key
```
4. Защитите файл конфига правами доступа только для пользователя сервиса.
5. Запустите приложение.

## 2. Что должна сделать внешняя система

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
3. Определить `issuer`, `audience`, `required_scope`.
4. Выдавать короткоживущие JWT (рекомендуемо 5-15 минут) с `kid` и claims:
`iss`, `aud`, `exp`, `nbf`, `iat`, `scope` (должен содержать `required_scope`), желательно `jti`.

### 2.1 Доверие к TLS-сертификату JWKS

`leshy-controller` проверяет TLS-цепочку JWKS по системному trust store хоста.

Требования:
1. `jwks_url` должен быть `https://...` и сертификат должен быть валиден для хоста.
2. Самоподписанный сертификат без доверенной CA приведет к ошибке загрузки JWKS.
3. Для стенда:
   - используйте сертификат от доверенной CA;
   - или добавьте тестовую CA в trust store узла с `leshy-controller`;
   - или используйте `mkcert` и установите локальную CA в trust store.

## 3. HTTP режим (`api_server_mode: http`)

### 3.1 Первичная конфигурация (`POST /api/v1/management/settings`)

```bash
curl -X POST "https://<host>:9090/api/v1/management/settings" \
  -k \
  -H "Content-Type: application/json" \
  -H "X-Bootstrap-Token: REPLACE_WITH_RANDOM_TOKEN" \
  -d '{
    "issuer": "https://auth.example.com",
    "audience": "leshy-controller",
    "jwks_url": "https://auth.example.com/.well-known/jwks.json",
    "required_scope": "allow:write",
    "guarded_ports_range": "3389-3390",
    "iface": "ens18",
    "handshake_window_sec": 600,
    "inactive_timer_sec": 300
  }'
```

### 3.2 Вызов `/allow`

```bash
curl -X POST "https://<host>:9090/api/v1/allow" \
  -k \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.10","port":3389}'
```

### 3.3 Обновление настроек (`PATCH /api/v1/management/settings`)

```bash
curl -X PATCH "https://<host>:9090/api/v1/management/settings" \
  -k \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "issuer": "https://auth.example.com",
    "audience": "leshy-controller",
    "jwks_url": "https://auth.example.com/.well-known/jwks.json",
    "required_scope": "allow:write",
    "guarded_ports_range": "3389-3395",
    "iface": "ens18",
    "handshake_window_sec": 900,
    "inactive_timer_sec": 300
  }'
```

Примечание: `PATCH` ожидает полный объект settings (не partial update).

### 3.4 Экстренная блокировка (`POST /api/v1/management/block`)

```bash
curl -X POST "https://<host>:9090/api/v1/management/block" \
  -k \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>"
```

## 4. gRPC режим (`api_server_mode: grpc`)

Используется тот же контракт: `docs/api/grpc/leshy_controller_v1.proto`.

Примеры ниже для self-signed TLS (`-insecure`). Для доверенного сертификата уберите `-insecure`.

### 4.1 Первичная конфигурация (`ManagementService/CreateSettings`)

```bash
grpcurl -insecure \
  -import-path docs/api/grpc \
  -proto leshy_controller_v1.proto \
  -H 'x-bootstrap-token: REPLACE_WITH_RANDOM_TOKEN' \
  -d '{
    "issuer": "https://auth.example.com",
    "audience": "leshy-controller",
    "jwks_url": "https://auth.example.com/.well-known/jwks.json",
    "required_scope": "allow:write",
    "guarded_ports_range": "3389-3390",
    "iface": "ens18",
    "handshake_window_sec": 600,
    "inactive_timer_sec": 300
  }' \
  <host>:9090 \
  leshy.controller.v1.ManagementService/CreateSettings
```

### 4.2 Разрешение подключения (`FilterService/Allow`)

```bash
grpcurl -insecure \
  -import-path docs/api/grpc \
  -proto leshy_controller_v1.proto \
  -H 'authorization: Bearer <JWT_ACCESS_TOKEN>' \
  -d '{"ip":"203.0.113.10","port":3389}' \
  <host>:9090 \
  leshy.controller.v1.FilterService/Allow
```

### 4.3 Просмотр статистики (`FilterService/Stats`)

```bash
grpcurl -insecure \
  -import-path docs/api/grpc \
  -proto leshy_controller_v1.proto \
  -H 'authorization: Bearer <JWT_ACCESS_TOKEN>' \
  -d '{}' \
  <host>:9090 \
  leshy.controller.v1.FilterService/Stats
```

### 4.4 Обновление настроек (`ManagementService/UpdateSettings`)

```bash
grpcurl -insecure \
  -import-path docs/api/grpc \
  -proto leshy_controller_v1.proto \
  -H 'authorization: Bearer <JWT_ACCESS_TOKEN>' \
  -d '{
    "issuer": "https://auth.example.com",
    "audience": "leshy-controller",
    "jwks_url": "https://auth.example.com/.well-known/jwks.json",
    "required_scope": "allow:write",
    "guarded_ports_range": "3389-3395",
    "iface": "ens18",
    "handshake_window_sec": 900,
    "inactive_timer_sec": 300
  }' \
  <host>:9090 \
  leshy.controller.v1.ManagementService/UpdateSettings
```

### 4.5 Экстренная блокировка (`ManagementService/Block`)

```bash
grpcurl -insecure \
  -import-path docs/api/grpc \
  -proto leshy_controller_v1.proto \
  -H 'authorization: Bearer <JWT_ACCESS_TOKEN>' \
  -d '{}' \
  <host>:9090 \
  leshy.controller.v1.ManagementService/Block
```

## 5. Пояснение по runtime-параметрам

- `handshake_window_sec` — окно действия временной авторизации из `/allow` (pending).
- `inactive_timer_sec` — TTL неактивности для `active_flows`; при трафике по активному flow TTL продлевается.
