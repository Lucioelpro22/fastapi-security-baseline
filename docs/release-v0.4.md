# v0.4 release notes

v0.4 extends the baseline from single access-token protection to a security
model that supports longer-lived client sessions and credential upgrades. The
release is intended for integration testing and deployment review. It is not a
claim that every deployment is production-ready by default.

## New capabilities

### Refresh sessions

Clients can maintain a session without extending an access token indefinitely.
Refresh credentials are rotated on use, and reuse of a previously rotated
credential is treated as a replay signal. Operators should revoke the affected
session family and investigate the audit event.

### Signing-key rollover

The authentication layer supports an active signing key and a controlled
verification overlap during rollover. Keep the old key available only for the
short overlap required by the deployment. Remove it after all tokens issued
under it have expired or have been explicitly revoked.

### WebAuthn integration

The release defines the integration points needed to use WebAuthn for
privileged authentication. A deployment must supply a persistent credential
store, a stable relying-party ID, the expected origin, and a user-verification
policy. The baseline does not operate a browser ceremony, device inventory, or
account-recovery service for you.

### Operational controls

Revocation, MFA, readiness checks, request correlation, and structured audit
events are documented as one operating model. Redis remains the shared backend
for controls that must work consistently across API workers.

## Limits and deployment responsibilities

- Configure TLS before enabling browser authentication or WebAuthn.
- Use a managed database and Redis deployment with backups, access controls,
  monitoring, and tested restoration procedures.
- Load JWT keys, encryption keys, bootstrap credentials, and provider settings
  from an approved secret manager.
- Define session lifetime, refresh replay response, MFA recovery, and key
  rollover windows for each environment.
- Do not expose readiness details, audit streams, or administrative endpoints
  to unauthenticated public clients.
- Review the threat model and complete the
  [production checklist](production-checklist.md) before handling real users.

The project does not include a hosted identity provider, password reset,
account lockout policy, WAF, TLS termination, multi-tenant authorization, or a
complete incident-management workflow.

## Migration from v0.3

1. Create a database backup and record the current deployment configuration.
2. Provision the new key and session secrets through the secret provider. Keep
   the v0.3 signing key available during the planned verification overlap.
3. Configure the shared Redis backend for every API instance. Production must
   fail closed if Redis is unavailable.
4. Deploy v0.4 and verify `/health`, readiness, login, logout, MFA, refresh
   rotation, and revocation from two API workers.
5. Treat refresh-token reuse as a security event: revoke the session family,
   review the audit trail, and require re-authentication.
6. After the overlap window, remove the old signing key and confirm that old
   tokens are rejected or expired as intended.
7. If enabling WebAuthn, register credentials only after the relying-party ID
   and origin have been validated for the production hostname. Keep a tested
   recovery path for administrators.

## Verification checklist

Before release, run the test suite and lint checks, then verify these behaviors
in the target environment:

- Refresh credentials rotate and cannot be reused.
- Logout and incident revocation reject access and refresh credentials.
- Key rollover accepts only the configured overlap and rejects unknown keys.
- MFA and WebAuthn policy cannot be bypassed by selecting another token flow.
- Redis and database failures produce safe, observable readiness failures.
- Logs contain correlation IDs and event metadata without secrets or tokens.

