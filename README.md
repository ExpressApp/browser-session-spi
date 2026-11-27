# Browser Session SPI

REST-провайдер для Keycloak от **24.0.0** до **26.8.2** включительно. Сервер приложения получает одноразовый challenge по действующему access token пользователя, после чего браузер обменивает challenge и тот же токен на SSO-сессию Keycloak.

Для поддерживаемых версий используется один JAR. В Keycloak **26.6.0–26.6.2** доступен сценарий `Bearer` с `client_secret_post`. В этих патчах сервер возвращает `401` на `client_secret_basic` ещё до вызова провайдера и выполняет предварительную проверку DPoP proof, поэтому обмен challenge с `DPoP` тоже отклоняется. Полный сценарий в ветке 26.6 работает начиная с **26.6.3**. [Регрессия Keycloak #49611](https://github.com/keycloak/keycloak/issues/49611) · [Исправление в 26.6.3](https://www.keycloak.org/2026/06/keycloak-2663-released)

## Сборка

Нужны JDK 17 или новее и Maven 3.6.3 или новее. Сборка по умолчанию использует API Keycloak 24.0.0 и создаёт байткод Java 17. Для запуска используйте версию Java, которую поддерживает ваш сервер.

```bash
mvn clean verify
```

Готовый JAR появится в `target/browser-session-spi-0.1.0-SNAPSHOT.jar`.

## Установка

1. Скопируйте JAR в каталог `providers/` установки Keycloak.
2. Выполните `bin/kc.sh build` и запустите сервер. Для DPoP на Keycloak 24, 25 и 26.0–26.3 соберите сервер командой `bin/kc.sh build --features=dpop`. Начиная с 26.4 DPoP включён по умолчанию. [Поддержка DPoP в Keycloak 26.4](https://www.keycloak.org/2025/10/dpop-support-26-4)
3. Включите **Client authentication** у нужного OIDC-клиента. Через Admin REST API добавьте `"browser-session.enabled": "true"` в его `attributes`, сохранив остальные атрибуты. Этот флаг разрешает клиенту создавать браузерную SSO-сессию из выданного ему access token.
4. Если браузер обращается к Keycloak с другого origin, добавьте этот origin в **Web origins** клиента. Браузер должен разрешать установку cookie Keycloak с этого origin.

Challenge по умолчанию действует до 60 секунд и истекает вместе с access token, если токен истекает раньше. Срок в секундах настраивается параметром `--spi-realm-restapi-extension-sso-challenge-ttl=60` при запуске сервера.

## Получение challenge

`POST /realms/{realm}/sso/init` принимает `application/x-www-form-urlencoded`. Вызов выполняется с сервера приложения, где хранится `client_secret`.

| Поле | Значение |
| --- | --- |
| `client_id`, `client_secret` | Для `client_secret_post` передаются в форме. Для `client_secret_basic` передаются через `Authorization: Basic …`. |
| `token` | Access token пользователя, выданный этому клиенту в том же realm. |
| `token_type` | `Bearer` или `DPoP`. Регистр значения не важен. |
| `state` | Строка, которую браузер передаст при обмене challenge. |

Для DPoP получите привязанный access token через Authorization Code Flow с заголовком `DPoP` при обмене кода. Затем для `/sso/init` сформируйте отдельный proof для `POST` на этот URL. Proof содержит `ath` от переданного access token и подписывается ключом, к которому привязан токен. [Документация DPoP](https://www.keycloak.org/securing-apps/dpop)

Успешный ответ `200 OK` содержит `challenge`, `expires_in` в секундах и исходный `state`.

```json
{
  "challenge": "1BWxqzEW9FjQASoANG4oETIlZIBlGcI-FbZf0iiR6OA",
  "expires_in": 60,
  "state": "request-123"
}
```

## Обмен challenge в браузере

`GET /realms/{realm}/sso/challenge` принимает `state` и `challenge` в query string, а в `Authorization` передаётся тот же access token со схемой `Bearer` или `DPoP`. Для DPoP нужен новый proof для `GET` на URL `/sso/challenge` без query string.

```js
const url = new URL(`realms/${encodeURIComponent(realm)}/sso/challenge`, keycloakUrl);
url.search = new URLSearchParams({ state, challenge });

const response = await fetch(url, {
  credentials: "include",
  headers: { Authorization: `Bearer ${accessToken}` },
});
```

В примере `keycloakUrl` — базовый URL установки Keycloak с завершающим `/`. При `200 OK` браузер получает штатные `KEYCLOAK_IDENTITY` и `KEYCLOAK_SESSION` и дополнительную `HttpOnly` cookie `KC_SSO_SESSION` с ID новой сессии пользователя. На HTTPS у `KC_SSO_SESSION` также установлены `Secure` и `SameSite=None`. Новый сеанс имеет собственный жизненный цикл Keycloak и сохраняет время исходной аутентификации.

Ошибки содержат JSON с полем `error`. `400 invalid_grant` означает, что challenge истёк, уже был погашен или не совпал с токеном и `state`. `401` возвращается при ошибке проверки секретного ключа клиента или токена. `403` возвращается, когда у клиента или origin нет доступа к операции либо realm требует HTTPS.

## Проверка совместимости

Полный тест прошёл на Keycloak 24.0.0, 24.0.5, 24.0.10, 25.0.0, 25.0.6, первых патчах веток 26.0–26.5, а также 26.6.3, 26.7.0 и 26.8.2.

Тест запускает копию распакованного дистрибутива на локальном HTTPS с базой в памяти. Он проверяет обе схемы аутентификации клиента, CORS, вход по cookie, DPoP, одноразовость и срок жизни challenge, а также отзыв доступа после завершения исходной сессии. Для запуска нужны Python 3, пакеты `requests` и `cryptography` и Java для проверяемой версии Keycloak.

```bash
python3 tests/sso_compatibility.py /path/to/keycloak-26.8.2 target/browser-session-spi-0.1.0-SNAPSHOT.jar
```

[REST-провайдеры Keycloak](https://www.keycloak.org/docs/latest/server_development/#_providers) · [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)
