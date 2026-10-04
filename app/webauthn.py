"""WebAuthn provider boundary.

WebAuthn ceremonies must be implemented by a maintained, audited library. This
module deliberately contains no credential parsing or cryptography. The
disabled provider makes accidental partial enablement fail closed while giving
an integration point for a provider such as ``webauthn`` in a later release.
"""
from dataclasses import dataclass
from typing import Protocol


class WebAuthnNotConfigured(RuntimeError):
    """Raised when a passkey provider has not been configured."""


@dataclass(frozen=True)
class WebAuthnSettings:
    rp_id: str
    rp_name: str
    origin: str


class WebAuthnProvider(Protocol):
    def registration_options(self, *, user_id: str, username: str) -> dict: ...

    def authentication_options(self, *, username: str | None = None) -> dict: ...


class DisabledWebAuthnProvider:
    """Safe default; no WebAuthn ceremony can run until a provider is wired."""

    def registration_options(self, *, user_id: str, username: str) -> dict:
        raise WebAuthnNotConfigured("WebAuthn provider is not configured")

    def authentication_options(self, *, username: str | None = None) -> dict:
        raise WebAuthnNotConfigured("WebAuthn provider is not configured")


def provider_for_settings(*, enabled: bool, rp_id: str | None, rp_name: str, origin: str | None) -> WebAuthnProvider:
    """Return only a fully configured implementation boundary.

    The current release intentionally returns the disabled provider even when
    settings are present. This prevents deployment configuration from being
    mistaken for a complete passkey implementation.
    """
    return DisabledWebAuthnProvider()
