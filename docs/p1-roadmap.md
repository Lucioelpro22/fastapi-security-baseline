# P1 hardening roadmap

P1 extends the v0.2 baseline with controls needed when users remain
authenticated across multiple requests, devices, and deployments. An item is
complete only when its tests, documentation, and operational checks are present.

## MFA for privileged roles

Administrators, operators, and auditors must be able to enroll and verify a
second factor. The default design target is TOTP with recovery codes stored as
one-way hashes. Secrets and recovery codes must never appear in API responses,
audit events, or application logs. Enrollment, factor reset, failed attempts,
and recovery-code use must be auditable and rate limited.

Acceptance criteria:

- MFA is required for privileged sign-in when enabled by policy.
- An account cannot bypass MFA by requesting another access-token flow.
- Recovery codes are single-use and protected by the same rate limits as login.
- Tests cover enrollment, valid and invalid codes, replay, reset, and lockout.

## Token and session revocation

Short JWT expiry limits exposure but does not revoke a token immediately. P1
must provide a server-side revocation mechanism keyed by token identifier or
session identifier, with a bounded retention period. Password changes,
privileged-role changes, logout, and incident response must be able to revoke
the relevant sessions.

Acceptance criteria:

- Every access token has a unique identifier and a bounded lifetime.
- Revoked tokens are rejected before authorization is evaluated.
- Revocation works across API instances through the configured shared backend.
- The implementation fails closed when the production revocation backend is
  unavailable.

## External secret provider

Production secrets must be loaded from an approved provider rather than from a
checked-in file or process arguments. The provider interface should support
startup loading, explicit allowlisted keys, and clear failure when a required
secret is missing. Development and tests may use environment variables.

Acceptance criteria:

- Production startup rejects missing or unavailable required secrets.
- Secret values are not included in errors, readiness responses, or logs.
- Provider access is injectable in tests and has no effect on development mode.
- Rotation behavior and rollback steps are documented.

## Readiness and deployment gate

Readiness must report whether required dependencies and security configuration
are usable for the current environment. It should distinguish liveness from
readiness: a live process can answer `/health` while a production deployment is
not ready to receive traffic.

The readiness contract should check configuration validation, database
connectivity, Redis connectivity, secret-provider status, and migration state.
Responses must contain aggregate status and safe reason codes only; never expose
connection strings, secret values, or stack traces. CI and deployment tooling
must exercise both a ready case and each failed dependency case.

## Release gate

P1 is ready for production review when all four areas have unit/integration
tests, threat-model updates, API documentation, operational runbooks, and a
passing CI job. A passing local test run alone is not evidence that production
dependencies are configured correctly.
