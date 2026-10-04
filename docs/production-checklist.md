# Production checklist

Complete these items before the service handles real users:

- [ ] Set `ENVIRONMENT=production` and keep `DEBUG=false`.
- [ ] Generate and store a unique `JWT_SECRET` (32+ characters) in a secret manager.
- [ ] Set a unique `ADMIN_PASSWORD` (16+ characters), then rotate it after bootstrap.
- [ ] Configure a reachable authenticated Redis instance through `REDIS_URL`.
- [ ] Configure a persistent database through `DATABASE_URL`.
- [ ] Set `ALLOWED_ORIGINS` to exact HTTPS origins; do not use a wildcard.
- [ ] Put the API behind TLS termination and verify HSTS at the edge.
- [ ] Send structured audit logs to a restricted, monitored sink.
- [ ] Configure alerts for repeated 401s, 429s, 503s, and Redis failures.
- [ ] Run `pytest`, linting, dependency auditing, and the container image scan in CI.
- [ ] Build images with the committed Dockerfile and `--pull`; review the generated SBOM as a release artifact.
- [ ] Pin production base images and service images by digest in the deployment manifest after review.
- [ ] Confirm the runtime image runs as UID 10001, drops Linux capabilities, uses a read-only root filesystem, and has a passing healthcheck.
- [ ] Set CPU, memory, and process limits for every container; keep Redis on the private service network.
- [ ] Test secret rotation, backup restoration, and incident response.
- [ ] Replace the reference identity repository with a managed user store before scale.
- [ ] Enable MFA for administrators, operators, and auditors; verify recovery and lockout procedures.
- [ ] If enabling passkeys, wire an audited WebAuthn provider; verify RP ID/origin binding, one-time challenges, credential storage, and recovery before exposing the endpoints.
- [ ] Configure token/session revocation and test revocation during password reset, logout, and incident response.
- [ ] Load JWT and bootstrap secrets through an approved external secret provider in production.
- [ ] Keep the readiness check protected from public access, or expose only non-sensitive aggregate status.
- [ ] Require a passing readiness check in the deployment gate and retain its audit result.

The application fails closed for unsafe production settings and for an
unavailable production rate-limit backend. Treat either condition as a release
block or an incident requiring investigation.
