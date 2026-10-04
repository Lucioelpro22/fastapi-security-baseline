# FastAPI Security Baseline

A small, reusable starting point for production-minded FastAPI services. It demonstrates secure configuration validation, Argon2 password hashing, short-lived JWTs with per-token `jti` revocation, SQLAlchemy-backed users, role-based access control, Redis-backed login rate limiting, structured audit events, security headers, non-root Docker execution, and CI security checks.

Current release: **v0.4**. See the [v0.4 release notes](docs/release-v0.4.md)
and [the changelog](CHANGELOG.md) for the security changes and migration steps.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
# Replace JWT_SECRET, MFA_ENCRYPTION_KEY, and ADMIN_PASSWORD with unique values.
pytest
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the API documentation.

## Security status and scope

This is a baseline and teaching project. The v0.4 reference implementation
persists users through SQLAlchemy, uses Redis for distributed login rate
limiting and revocation when configured, supports privileged-user MFA, and
provides short-lived access tokens with refresh-session controls. A production
deployment still needs a managed identity provider or user store, a managed
Redis instance, TLS at the edge, an approved secret provider, monitoring,
backups, and incident response procedures.

The v0.4 milestone covers the controls required to operate the baseline safely
over multiple sessions: MFA for privileged roles, token and session revocation,
refresh-token rotation, key-rotation hooks, WebAuthn integration points, an
external secret provider interface, and readiness checks. These controls still
require deployment-specific configuration and operational validation before a
production rollout.

The service fails closed for unsafe production configuration. It does not provide
an identity provider, a secrets vault, a complete incident-management system,
or a hosted WebAuthn enrollment service. WebAuthn credentials must be backed by
a persistent, protected credential store and an origin- and RP-ID configuration
that matches the deployed hostname.

See [docs/architecture.md](docs/architecture.md), [docs/api.md](docs/api.md),
[docs/threat-model.md](docs/threat-model.md), and the
[production checklist](docs/production-checklist.md). See the
[v0.4 release notes](docs/release-v0.4.md) for migration guidance.
