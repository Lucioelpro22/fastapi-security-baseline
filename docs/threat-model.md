# Threat model

## Trust boundaries

The public client crosses the edge proxy into the FastAPI process. The API then
crosses separate boundaries to the identity store, Redis, and the audit sink.
Secrets are supplied by the deployment environment and are not accepted from
request bodies.

## Assets

- User credentials, access tokens, and account status.
- Authorization decisions and audit records.
- Redis rate-limit counters and persistent user records.
- Configuration secrets and the service's availability.

## Primary threats and controls

| Threat | Control in this baseline | Deployment responsibility |
| --- | --- | --- |
| Password guessing | Per-client login rate limit, generic 401 responses, Argon2 hashing | Use Redis and alert on repeated failures |
| Token forgery or replay | HS256 signature, issuer/audience/type checks, required claims, short expiry | Rotate the secret and terminate sessions when required |
| Refresh-token replay | Atomic Redis rotation, expiring consumed-token tombstones, family revocation | Use standalone Redis 6.2+, invalidate pre-upgrade sessions, and do not mix old/new workers |
| Cross-origin token use | Explicit `ALLOWED_ORIGINS`, credentials disabled | Keep the list small and review it per environment |
| Configuration drift | Production validation for secrets, Redis, debug mode, and persistent DB | Inject secrets through a secret manager |
| Redis outage bypassing controls | Production fail-closed response (503) | Monitor Redis and define an incident path |
| Sensitive data in logs | Structured audit events omit passwords and request bodies | Restrict log access and set retention |

## Out of scope

This reference does not provide account lockout,
password reset, TLS termination, WAF protection, or a multi-tenant policy
engine. Add those controls before exposing a real user population.

## Abuse cases to verify before release

1. A forged token, wrong audience, expired token, and non-access token are all rejected.
2. Requests from an unapproved origin do not receive CORS permission.
3. A Redis failure in production returns a controlled 503 instead of disabling the limiter.
4. A production process cannot start with debug enabled, demo credentials, or ephemeral state.

5. Reusing a consumed refresh token revokes descendants across workers; concurrent rotation yields at most one replacement, which becomes unusable after replay.
6. Persisted account session-version changes reject old access and refresh credentials.
