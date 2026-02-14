# Примеры


## 1. Подготовка bootstrap-токена

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


### 2.2 Пошаговый пример для stub-auth как подключить внешний auth-сервис

[GitHub Gist](https://gist.github.com/devalv/33998fbcf2d1ae3ba53c835340ba3614)


## 3. Первичная конфигурация приложения (`/api/v1/management/settings`)

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

## 4. Вызов `/allow` из внешней системы

1. Внешняя система выпускает JWT приватным ключом `Ed25519`.
2. Отправляет запрос:
```bash
curl -X POST "http://<host>:9090/api/v1/allow" \
  -H "Authorization: Bearer <JWT_ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.10","port":3389}'
```

## 5. Обновление настроек (`PATCH /api/v1/management/settings`)

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

## 6. Экстренная блокировка (`POST /api/v1/management/block`)

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
