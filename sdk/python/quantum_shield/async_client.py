"""QuantumShield SDK — async client (requires httpx).

Install with:  pip install quantum-shield[async]

Quick start::

    import asyncio
    from quantum_shield.async_client import AsyncQuantumShield

    async def main():
        async with AsyncQuantumShield("http://localhost:8080") as qs:
            await qs.auth("alice", ["read", "write"],
                          bootstrap_secret="my-secret")
            key = await qs.keys.generate()
            enc = await qs.crypto.encrypt(key.key_id, b"hello")
            dec = await qs.crypto.decrypt(key.key_id, enc.encrypted)
            print(dec.plaintext)  # b"hello"

    asyncio.run(main())
"""
from __future__ import annotations

import base64
from typing import Any

from .exceptions import _raise_for_status, QuantumShieldError
from .models import (
    CAInitResult, Certificate, CertVerifyResult, DecryptResult,
    DerivedKey, Encrypted, EncryptResult, FIPSReport, HealthStatus,
    KeyPair, PublicKey, Signature, Token, VerifyResult,
)

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False


class _AsyncHTTP:
    def __init__(self, base_url: str, timeout: float, verify_ssl: bool) -> None:
        if not _HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required for async support. "
                "Install with: pip install quantum-shield[async]"
            )
        self._base    = base_url.rstrip("/")
        self._timeout = timeout
        self._token: str | None = None
        self._client  = httpx.AsyncClient(
            base_url=self._base,
            timeout=timeout,
            verify=verify_ssl,
        )

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        return h

    async def request(self, method: str, path: str, body: Any = None,
                      token_override: str | None = None) -> dict:
        headers = self._headers()
        if token_override:
            headers["Authorization"] = f"Bearer {token_override}"
        resp = await self._client.request(
            method, path, json=body, headers=headers
        )
        if resp.status_code >= 400:
            try:
                body_dict = resp.json()
            except Exception:
                body_dict = {"error": resp.text}
            _raise_for_status(resp.status_code, body_dict)
        return resp.json() if resp.text.strip() else {}

    async def get(self, path: str) -> dict:
        return await self.request("GET", path)

    async def post(self, path: str, body: Any = None,
                   token_override: str | None = None) -> dict:
        return await self.request("POST", path, body, token_override)

    async def delete(self, path: str) -> dict:
        return await self.request("DELETE", path)

    async def aclose(self) -> None:
        await self._client.aclose()


# ── Async sub-clients ──────────────────────────────────────────────────────────

class _AsyncAuthClient:
    def __init__(self, http: _AsyncHTTP) -> None:
        self._http = http

    async def issue(self, user_id: str, roles: list[str],
                    bootstrap_secret: str | None = None) -> Token:
        d = await self._http.post(
            "/auth/token",
            {"user_id": user_id, "roles": roles},
            token_override=bootstrap_secret,
        )
        tok = Token.from_dict(d)
        self._http._token = tok.token
        return tok

    async def verify(self, token: str) -> dict:
        return await self._http.post("/auth/verify", {"token": token})

    async def revoke(self, token: str) -> None:
        await self._http.post("/auth/revoke", {"token": token})


class _AsyncKeysClient:
    def __init__(self, http: _AsyncHTTP) -> None:
        self._http = http

    async def generate(self, level: str = "ML-KEM-768") -> KeyPair:
        d = await self._http.post("/keys/generate", {"level": level})
        return KeyPair.from_dict(d)

    async def list(self) -> list[str]:
        d = await self._http.get("/keys")
        return d.get("key_ids", [])

    async def public_key(self, key_id: str) -> PublicKey:
        d = await self._http.get(f"/keys/{key_id}/public")
        return PublicKey.from_dict(d)

    async def export(self, key_id: str, password: str) -> dict:
        return await self._http.post(f"/keys/{key_id}/export", {"password": password})

    async def import_key(self, wrapped: dict, password: str) -> KeyPair:
        d = await self._http.post("/keys/import", {"wrapped": wrapped, "password": password})
        return KeyPair.from_dict(d)


class _AsyncCryptoClient:
    def __init__(self, http: _AsyncHTTP) -> None:
        self._http = http

    async def encrypt(self, key_id: str, plaintext: bytes | str) -> EncryptResult:
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode("latin-1")
        d = await self._http.post("/encrypt", {"key_id": key_id, "plaintext": plaintext})
        return EncryptResult.from_dict(d)

    async def decrypt(self, key_id: str, encrypted: Encrypted) -> DecryptResult:
        d = await self._http.post("/decrypt", {
            "key_id":    key_id,
            "encrypted": encrypted.to_dict(),
        })
        return DecryptResult.from_dict(d)

    async def sign(self, key_id: str, message: bytes | str) -> Signature:
        if isinstance(message, str):
            message = message.encode()
        d = await self._http.post("/sign", {
            "key_id":  key_id,
            "message": base64.b64encode(message).decode(),
        })
        return Signature.from_dict(d)

    async def verify_signature(self, message: bytes | str, signature: str,
                               public_key: str) -> VerifyResult:
        if isinstance(message, str):
            message = message.encode()
        d = await self._http.post("/verify-signature", {
            "message":    base64.b64encode(message).decode(),
            "signature":  signature,
            "public_key": public_key,
        })
        return VerifyResult.from_dict(d)


class _AsyncCAClient:
    def __init__(self, http: _AsyncHTTP) -> None:
        self._http = http

    async def init(self, subject: str) -> CAInitResult:
        d = await self._http.post("/ca/init", {"subject": subject})
        return CAInitResult.from_dict(d)

    async def sign(self, subject: str, public_key: str,
                   public_key_type: str = "ML-KEM-768",
                   ttl_days: int = 365) -> Certificate:
        d = await self._http.post("/ca/sign", {
            "subject":         subject,
            "public_key":      public_key,
            "public_key_type": public_key_type,
            "ttl_days":        ttl_days,
        })
        return Certificate.from_dict(d)

    async def verify(self, certificate: Certificate | dict) -> CertVerifyResult:
        cert_dict = certificate.raw if isinstance(certificate, Certificate) else certificate
        d = await self._http.post("/ca/verify", {"certificate": cert_dict})
        result = CertVerifyResult.from_dict(d)
        if not result.valid:
            from .exceptions import CertificateVerificationError
            raise CertificateVerificationError(
                result.error or "certificate verification failed"
            )
        return result

    async def revoke(self, serial: str) -> None:
        await self._http.post("/ca/revoke", {"serial": serial})

    async def get_certificate(self) -> Certificate:
        d = await self._http.get("/ca/certificate")
        return Certificate.from_dict(d)

    async def get_crl(self) -> dict:
        return await self._http.get("/ca/crl")


class _AsyncHealthClient:
    def __init__(self, http: _AsyncHTTP) -> None:
        self._http = http

    async def status(self) -> HealthStatus:
        d = await self._http.get("/")
        return HealthStatus.from_dict(d)

    async def live(self) -> bool:
        try:
            await self._http.get("/health/live")
            return True
        except Exception:
            return False

    async def fips(self) -> FIPSReport:
        d = await self._http.get("/health/fips")
        return FIPSReport.from_dict(d)


# ── Main async client ─────────────────────────────────────────────────────────

class AsyncQuantumShield:
    """Async QuantumShield client backed by httpx.

    Use as an async context manager for automatic cleanup::

        async with AsyncQuantumShield("http://localhost:8080") as qs:
            await qs.auth("alice", ["read", "write"])
            key = await qs.keys.generate()

    Or manage lifetime manually::

        qs = AsyncQuantumShield("http://localhost:8080")
        try:
            await qs.auth("alice", ["write"])
            ...
        finally:
            await qs.close()
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        bootstrap_secret: str | None = None,
        timeout: float = 30.0,
        verify_ssl: bool = True,
    ) -> None:
        self._http = _AsyncHTTP(base_url, timeout, verify_ssl)
        self._bootstrap_secret = bootstrap_secret
        if token:
            self._http._token = token

        self.health = _AsyncHealthClient(self._http)
        self.auth_  = _AsyncAuthClient(self._http)
        self.keys   = _AsyncKeysClient(self._http)
        self.crypto = _AsyncCryptoClient(self._http)
        self.ca     = _AsyncCAClient(self._http)

    async def auth(self, user_id: str, roles: list[str],
                   bootstrap_secret: str | None = None) -> Token:
        """Issue a token and configure it for all subsequent requests."""
        secret = bootstrap_secret or self._bootstrap_secret
        return await self.auth_.issue(user_id, roles, bootstrap_secret=secret)

    @property
    def token(self) -> str | None:
        return self._http._token

    @token.setter
    def token(self, value: str | None) -> None:
        self._http._token = value

    async def close(self) -> None:
        """Release the underlying httpx.AsyncClient."""
        await self._http.aclose()

    async def __aenter__(self) -> "AsyncQuantumShield":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    def __repr__(self) -> str:
        return f"AsyncQuantumShield(base_url={self._http._base!r})"
