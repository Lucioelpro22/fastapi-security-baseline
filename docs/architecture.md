# Architecture

The API is split into configuration, authentication, audit, and HTTP middleware concerns.

- `config.py` validates environment-dependent settings and rejects weak production defaults.
- `security.py` provides Argon2 password hashing and short-lived JWT access tokens.
- `main.py` exposes health, token, and protected-user endpoints and applies headers/rate limits.
- `audit.py` emits structured events without credentials or request bodies.

Production integration points are the user repository, Redis-backed rate limiter, secret manager, and centralized audit sink.
