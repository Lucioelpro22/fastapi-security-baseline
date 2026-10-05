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
| `MFA_ENCRYPTION_KEY` | MFA in production | Fernet key used only to encrypt TOTP secrets; generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `JWT_ISSUER` / `JWT_AUDIENCE` | No | JWT scope checks |
| `ADMIN_PASSWORD` | Production | Initial admin password, at least 16 characters |
| `REDIS_URL` | Production | Distributed rate limiter backend |
| `DATABASE_URL` | No | Persistent user store; no `:memory:` backend in production |
| `ALLOWED_ORIGINS` | No | JSON list of exact browser origins |
| `RATE_LIMIT_PER_MINUTE` | No | Login attempts per client and minute |
| `DEBUG` | No | Must be false in production |

Never commit `.env` files or place credentials in the request payload beyond
the login password. Use a managed secret store in production.

`MFA_ENCRYPTION_KEY` is deliberately independent from `JWT_SECRET`. During a
development migration, records written by older releases can still be read
with the legacy JWT-derived key; newly encrypted records use the dedicated
key. Production MFA operations fail closed unless the dedicated key is
configured. Enabling MFA increments the account session version and invalidates
all previously issued access and refresh sessions for that account.
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

## Refresh sessions

`POST /auth/token` also returns an opaque `refresh_token`.
`POST /auth/refresh` accepts that value and replaces it with a one-time token
in the same family. The entire family expires after `REFRESH_TOKEN_DAYS`
(default 30) from login; rotating does not extend that absolute deadline.
Replaying a consumed token returns `401` and revokes all family descendants.
This revokes refresh capability; already issued access tokens retain their
normal short lifetime unless the account session version is also advanced.

Production refresh state requires standalone Redis 6.2 or newer, with Lua
scripting enabled (`SET EXAT` is used). Redis Cluster is unsupported: rotation
accesses dynamically discovered family keys and multiple keys without a shared
cluster hash tag. Redis operations atomically check revocation, preserve the
consumed-token digest as a tombstone, and store the replacement. Tombstones,
replacement tokens and replay revocations expire at the original session
deadline. `/auth/refresh` returns `503` on production Redis outages, with no
memory fallback.
Development/test memory state is process-local and cannot provide cross-worker
revocation. Run `TEST_REDIS_URL=redis://localhost:6379/15 pytest` against a
dedicated Redis 7+ test database to include the shared-worker integration tests;
CI runs them against its disposable Redis service.

### Upgrade from the previous Redis rotation implementation

The previous implementation deleted consumed token keys, so their family
mapping cannot be reconstructed after upgrading. Before reopening refresh
traffic, drain workers, deploy this implementation to every worker, and advance
each persisted user's `session_version` once in a reviewed database migration.
This invalidates previously issued access and refresh sessions and requires
users to authenticate again. Verify an old credential receives `401` and a
fresh login/refresh succeeds before reopening traffic. Do not mix old and new
rotation workers during deployment. The migration is an operational action and
is not executed by the application or by this code change.

Rollback to an older implementation requires the same drained-worker and
persisted session-version invalidation procedure. Older workers do not
recognize consumed-token tombstones and can treat them as live tokens; never
roll back against still-authorized sessions in the new refresh keyspace.
