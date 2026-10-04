# Changelog

## Unreleased

- Added a dedicated `MFA_ENCRYPTION_KEY`; MFA TOTP data is no longer coupled to
  JWT signing-key rotation.
- MFA activation now increments the account session version and invalidates
  existing access and refresh sessions.

All notable changes to this project are documented here. Versions before
v0.4 were development milestones and should not be treated as production
compatibility guarantees.

## [Unreleased]

Changes for the next release will be documented here.

## [0.4.0] - 2026-10-04

### Added

- Refresh-session handling with rotation and replay detection.
- JWT signing-key rotation hooks with an explicit active-key policy.
- WebAuthn integration points for stronger authentication of privileged users.
- Operational documentation for token migration, key rollover, and recovery.
- Release and deployment guidance for the new authentication state.

### Hardened

- Revocation and logout remain enforced across workers when Redis is configured.
- Production configuration continues to fail closed when required state or
  security dependencies are unavailable.
- Authentication flows preserve request correlation and structured audit events
  without recording credentials, tokens, or recovery-code values.

### Limits

- WebAuthn is an integration surface, not a hosted credential registry.
- Key material, refresh-session storage, Redis, and the database remain the
  operator's responsibility.
- TLS termination, account recovery, lockout policy, device management, and
  incident response still require deployment-specific controls.

### Migration

1. Read [the v0.4 release notes](docs/release-v0.4.md).
2. Back up the database and verify that Redis is reachable from every API
   instance.
3. Configure the new signing-key and refresh-session settings through the
   approved secret provider. Do not copy secrets into `.env` files committed to
   source control.
4. Deploy the application with the old signing key available for the overlap
   window, then rotate to the new active key according to the documented
   rollover procedure.
5. Re-authenticate existing clients when required by the chosen session policy
   and verify logout, refresh replay detection, MFA, and readiness checks.

## [0.3.0]

- Added access-token revocation and logout.
- Added TOTP MFA and one-time recovery codes for administrators.
- Added external secret-provider interfaces, request correlation, and health
  probes.

## [0.2.0]

- Added SQLAlchemy-backed users, Redis login rate limiting, RBAC, and production
  configuration validation.

[Unreleased]: https://github.com/Lucioelpro22/fastapi-security-baseline/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Lucioelpro22/fastapi-security-baseline/releases/tag/v0.4.0
