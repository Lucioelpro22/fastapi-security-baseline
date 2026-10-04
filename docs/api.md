# API and configuration reference

## Endpoints

### `GET /health`

Returns `{"status":"ok"}`. Use this for a process health check; a deployment
readiness check should also verify its database and Redis dependencies.

### `POST /auth/token`

Accepts JSON with `username` (3–254 characters) and `password` (12–256
characters). On success it returns a short-lived bearer token:

```json
{"access_token": "<JWT>", "token_type": "bearer"}
```

Each access token contains a unique `jti`. The token remains valid until its
expiry or until it is revoked by logout.

Invalid credentials intentionally return the same `401` response for unknown
and known users. Excessive attempts return `429` with `Retry-After`.

### `POST /auth/logout`

Requires the current bearer token and revokes it through its expiry time. A
revoked token receives `401` on protected endpoints. Redis stores revocations
across workers in production; the process-local fallback is available only in
development and test.

### `GET /me`

Requires `Authorization: Bearer <JWT>` and returns the authenticated subject and
role. Invalid, expired, incorrectly typed, or incorrectly scoped tokens return
`401`.

### `GET /admin/status`

Requires a valid token with the `admin` role. Other roles receive `403`.

## Configuration

| Variable | Required | Purpose |
| --- | --- | --- |
| `ENVIRONMENT` | No | `development`, `test`, or `production` |
| `JWT_SECRET` | Yes | At least 32 unique characters |
| `JWT_ISSUER` / `JWT_AUDIENCE` | No | JWT scope checks |
| `ADMIN_PASSWORD` | Production | Initial admin password, at least 16 characters |
| `REDIS_URL` | Production | Distributed rate limiter backend |
| `DATABASE_URL` | No | Persistent user store; no `:memory:` backend in production |
| `ALLOWED_ORIGINS` | No | JSON list of exact browser origins |
| `RATE_LIMIT_PER_MINUTE` | No | Login attempts per client and minute |
| `DEBUG` | No | Must be false in production |

Never commit `.env` files or place credentials in the request payload beyond
the login password. Use a managed secret store in production.
# WebAuthn / passkeys

The baseline exposes two administrator-only integration points:

- `POST /auth/webauthn/register/options`
- `POST /auth/webauthn/authenticate/options`

They return `501` until an audited WebAuthn provider is installed and wired.
The project deliberately does not parse credential responses, verify
signatures, or implement challenge storage itself. A future provider must bind
the configured RP ID and HTTPS origin, persist challenges and credentials,
enforce one-time challenge use, verify user presence and verification, and
emit audit events without logging credential data.
