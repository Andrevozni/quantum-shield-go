"""QuantumShield SDK — synchronous client (uses httpx or requests).

Quick start::

    from quantum_shield import QuantumShield

    qs = QuantumShield("http://localhost:8080", bootstrap_secret="my-secret")
    qs.auth("alice", roles=["read", "write"])   # auto-sets token

    key  = qs.keys.generate()
    enc  = qs.crypto.encrypt(key.key_id, b"hello world")
    dec  = qs.crypto.decrypt(key.key_id, enc.encrypted)
    assert dec.plaintext == b"hello world"

    cert = qs.ca.sign("CN=alice.example.com", key.public_key, "ML-KEM-768")
    qs.ca.verify(cert)  # raises CertificateVerificationError if invalid
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .exceptions import _raise_for_status, QuantumShieldError
from .models import (
    CAInitResult, Certificate, CertVerifyResult, DecryptResult,
    DerivedKey, Encrypted, EncryptResult, FIPSReport, HealthStatus,
    KeyPair, PublicKey, Signature, Token, VerifyResult,
)


class _HTTP:
    """Thin urllib wrapper — zero external dependencies."""

    def __init__(self, base_url: str, timeout: float, verify_ssl: bool) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._verify = verify_ssl
        self._token: str | None = None

    def _headers(self, extra: dict | None = None) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._token:
            h["Authorization"] = f"Bearer {self._token}"
        if extra:
            h.update(extra)
        return h

    def request(self, method: str, path: str, body: Any = None,
                token_override: str | None = None) -> dict:
        url = self._base + path
        data = json.dumps(body).encode() if body is not None else None
        headers = self._headers()
        if token_override:
            headers["Authorization"] = f"Bearer {token_override}"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        # ssl_context only used if urllib raises ssl errors in older Pythons
        ctx = None
        if not self._verify:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as e:
            raw = e.read().decode()
            try:
                body_dict = json.loads(raw)
            except Exception:
                body_dict = {"error": raw or str(e)}
            _raise_for_status(e.code, body_dict)
            raise  # unreachable
        except urllib.error.URLError as e:
            raise QuantumShieldError(f"Connection error: {e.reason}") from e

    def get(self, path: str) -> dict:
        return self.request("GET", path)

    def post(self, path: str, body: Any = None, token_override: str | None = None) -> dict:
        return self.request("POST", path, body, token_override)

    def delete(self, path: str) -> dict:
        return self.request("DELETE", path)


# ── Sub-clients ────────────────────────────────────────────────────────────────

class _AuthClient:
    def __init__(self, http: _HTTP) -> None:
        self._http = http

    def issue(self, user_id: str, roles: list[str],
              bootstrap_secret: str | None = None) -> Token:
        """Issue a QST token for user_id with the given roles.

        Args:
            user_id:          Identifier for the principal (free-form string).
            roles:            List of role strings, e.g. ``["read", "write"]``.
            bootstrap_secret: Server bootstrap secret (required when the server
                              has ``BOOTSTRAP_SECRET`` set).

        Returns:
            :class:`Token` with the raw token string and metadata.

        Raises:
            :class:`AuthenticationError`: wrong bootstrap secret.
        """
        headers_override = None
        if bootstrap_secret:
            # Pass as Authorization: Bearer <secret> for the /auth/token endpoint.
            d = self._http.request(
                "POST", "/auth/token",
                body={"user_id": user_id, "roles": roles},
                token_override=bootstrap_secret,
            )
        else:
            d = self._http.post("/auth/token", {"user_id": user_id, "roles": roles})
        tok = Token.from_dict(d)
        self._http._token = tok.token
        return tok

    def verify(self, token: str) -> dict:
        """Verify a token and return its claims."""
        return self._http.post("/auth/verify", {"token": token})

    def revoke(self, token: str) -> None:
        """Revoke a token so it can no longer be used."""
        self._http.post("/auth/revoke", {"token": token})


class _KeysClient:
    def __init__(self, http: _HTTP) -> None:
        self._http = http

    def generate(self, level: str = "ML-KEM-768") -> KeyPair:
        """Generate a new ML-KEM keypair.

        Args:
            level: ``"ML-KEM-768"`` (default, NIST level 1) or
                   ``"ML-KEM-1024"`` (NIST level 3).

        Returns:
            :class:`KeyPair` with key_id and public_key (base64).
        """
        d = self._http.post("/keys/generate", {"level": level})
        return KeyPair.from_dict(d)

    def list(self) -> list[str]:
        """Return a list of all stored key IDs."""
        d = self._http.get("/keys")
        return d.get("key_ids", [])

    def public_key(self, key_id: str) -> PublicKey:
        """Retrieve the public encapsulation key for key_id."""
        d = self._http.get(f"/keys/{key_id}/public")
        return PublicKey.from_dict(d)

    def export(self, key_id: str, password: str) -> dict:
        """Export a key wrapped with password (Argon2id + AES-256-GCM)."""
        return self._http.post(f"/keys/{key_id}/export", {"password": password})

    def import_key(self, wrapped: dict, password: str) -> KeyPair:
        """Import a previously exported key."""
        d = self._http.post("/keys/import", {"wrapped": wrapped, "password": password})
        return KeyPair.from_dict(d)


class _CryptoClient:
    def __init__(self, http: _HTTP) -> None:
        self._http = http

    def encrypt(self, key_id: str, plaintext: bytes | str) -> EncryptResult:
        """Encrypt plaintext with ML-KEM-768 + AES-256-GCM.

        Args:
            key_id:    Key ID returned by :meth:`KeysClient.generate`.
            plaintext: Raw bytes or string to encrypt.

        Returns:
            :class:`EncryptResult` containing the nested ``encrypted`` object.
            Pass ``result.encrypted`` to :meth:`decrypt`.
        """
        if isinstance(plaintext, bytes):
            plaintext = plaintext.decode("latin-1")
        d = self._http.post("/encrypt", {"key_id": key_id, "plaintext": plaintext})
        return EncryptResult.from_dict(d)

    def decrypt(self, key_id: str, encrypted: Encrypted) -> DecryptResult:
        """Decrypt a previously encrypted message.

        Args:
            key_id:    Same key ID used for encryption.
            encrypted: The ``encrypted`` field from :class:`EncryptResult`.

        Returns:
            :class:`DecryptResult` with ``plaintext`` bytes.

        Raises:
            :class:`ReplayError`:   ciphertext already decrypted.
            :class:`ValidationError`: decryption failed.
        """
        d = self._http.post("/decrypt", {
            "key_id":    key_id,
            "encrypted": encrypted.to_dict(),
        })
        return DecryptResult.from_dict(d)

    def sign(self, key_id: str, message: bytes | str) -> Signature:
        """Sign a message with ML-DSA-65.

        Args:
            key_id:  Key ID to sign with.
            message: Message bytes or string.

        Returns:
            :class:`Signature` with base64 ``signature`` and ``public_key``.
        """
        if isinstance(message, str):
            message = message.encode()
        msg_b64 = base64.b64encode(message).decode()
        d = self._http.post("/sign", {"key_id": key_id, "message": msg_b64})
        return Signature.from_dict(d)

    def verify_signature(self, message: bytes | str, signature: str,
                         public_key: str) -> VerifyResult:
        """Verify an ML-DSA-65 signature.

        Args:
            message:    Original message.
            signature:  Base64 signature string.
            public_key: Base64 public key string.

        Returns:
            :class:`VerifyResult` with ``valid`` bool.
        """
        if isinstance(message, str):
            message = message.encode()
        d = self._http.post("/verify-signature", {
            "message":    base64.b64encode(message).decode(),
            "signature":  signature,
            "public_key": public_key,
        })
        return VerifyResult.from_dict(d)

    def slh_sign(self, key_id: str, message: bytes | str,
                 level: str = "128f") -> Signature:
        """Sign a message with SLH-DSA (stateless hash-based signature).

        Args:
            key_id:  Key ID to sign with.
            message: Message bytes or string.
            level:   Parameter set: ``"128f"`` | ``"128s"`` | ``"256f"`` | ``"256s"``.
        """
        if isinstance(message, str):
            message = message.encode()
        d = self._http.post("/slh-dsa/sign", {
            "key_id":  key_id,
            "message": base64.b64encode(message).decode(),
            "level":   level,
        })
        return Signature.from_dict(d)


class _KDFClient:
    def __init__(self, http: _HTTP) -> None:
        self._http = http

    def hkdf(self, input_key: bytes | str, info: str = "",
              length: int = 32) -> DerivedKey:
        """Derive a key using HKDF-SHA256.

        Args:
            input_key: Input key material (bytes or base64 string).
            info:      Context/application string for domain separation.
            length:    Output key length in bytes (default 32).

        Returns:
            :class:`DerivedKey` with base64 ``key``.
        """
        if isinstance(input_key, bytes):
            input_key = base64.b64encode(input_key).decode()
        d = self._http.post("/kdf/hkdf", {
            "input_key": input_key,
            "info":      info,
            "length":    length,
        })
        return DerivedKey.from_dict(d)

    def argon2(self, password: str, salt: str = "",
               time_cost: int = 3, memory_kb: int = 65536) -> DerivedKey:
        """Derive a key using Argon2id.

        Args:
            password:   Password or passphrase.
            salt:       Base64 salt (generated server-side if empty).
            time_cost:  Argon2id iterations (default 3).
            memory_kb:  Memory in KiB (default 65536 = 64 MiB).

        Returns:
            :class:`DerivedKey` with base64 ``key``.
        """
        body: dict = {"password": password, "time_cost": time_cost,
                      "memory_kb": memory_kb}
        if salt:
            body["salt"] = salt
        d = self._http.post("/kdf/argon2", body)
        return DerivedKey.from_dict(d)

    def generate_salt(self, length: int = 32) -> str:
        """Generate a cryptographically secure random salt (base64)."""
        d = self._http.post("/kdf/salt", {"length": length})
        return d.get("salt", "")


class _CAClient:
    def __init__(self, http: _HTTP) -> None:
        self._http = http

    def init(self, subject: str) -> CAInitResult:
        """Initialise the server's root CA (admin role required).

        Args:
            subject: X.500 distinguished name, e.g.
                     ``"CN=My Root CA,O=Acme Corp"``.

        Returns:
            :class:`CAInitResult` with the self-signed root :class:`Certificate`.
        """
        d = self._http.post("/ca/init", {"subject": subject})
        return CAInitResult.from_dict(d)

    def sign(self, subject: str, public_key: str,
             public_key_type: str = "ML-KEM-768",
             ttl_days: int = 365) -> Certificate:
        """Issue a leaf certificate signed by the root CA.

        Args:
            subject:         Distinguished name for the certificate subject.
            public_key:      Base64 public key of the subject.
            public_key_type: Algorithm of the public key (e.g. ``"ML-KEM-768"``).
            ttl_days:        Validity period in days (default 365).

        Returns:
            Signed :class:`Certificate`.
        """
        d = self._http.post("/ca/sign", {
            "subject":         subject,
            "public_key":      public_key,
            "public_key_type": public_key_type,
            "ttl_days":        ttl_days,
        })
        return Certificate.from_dict(d)

    def verify(self, certificate: Certificate | dict) -> CertVerifyResult:
        """Verify a certificate against the server's CA.

        Raises:
            :class:`CertificateVerificationError`: if ``valid`` is False.
        """
        cert_dict = certificate.raw if isinstance(certificate, Certificate) else certificate
        d = self._http.post("/ca/verify", {"certificate": cert_dict})
        result = CertVerifyResult.from_dict(d)
        if not result.valid:
            from .exceptions import CertificateVerificationError
            raise CertificateVerificationError(
                result.error or "certificate verification failed"
            )
        return result

    def revoke(self, serial: str) -> None:
        """Add a serial number to the CA's revocation list (admin role)."""
        self._http.post("/ca/revoke", {"serial": serial})

    def get_certificate(self) -> Certificate:
        """Retrieve the server's root CA certificate (public endpoint)."""
        d = self._http.get("/ca/certificate")
        return Certificate.from_dict(d)

    def get_crl(self) -> dict:
        """Retrieve the current Certificate Revocation List."""
        return self._http.get("/ca/crl")

    def create_intermediate(self, subject: str,
                            ttl_days: int = 3650) -> Certificate:
        """Create an intermediate CA signed by the root CA (admin role).

        Args:
            subject:  Distinguished name for the intermediate CA.
            ttl_days: Validity period (default 10 years).

        Returns:
            Intermediate CA :class:`Certificate`.
        """
        d = self._http.post("/ca/intermediate", {
            "subject":  subject,
            "ttl_days": ttl_days,
        })
        return Certificate.from_dict(d.get("certificate", d))

    def sign_via_intermediate(self, serial: str, subject: str,
                               public_key: str,
                               public_key_type: str = "ML-KEM-768",
                               ttl_days: int = 365) -> Certificate:
        """Issue a leaf certificate via an intermediate CA.

        Args:
            serial:  Serial number of the intermediate CA.
            subject: Distinguished name of the leaf.
        """
        d = self._http.post(f"/ca/intermediate/{serial}/sign", {
            "subject":         subject,
            "public_key":      public_key,
            "public_key_type": public_key_type,
            "ttl_days":        ttl_days,
        })
        return Certificate.from_dict(d)

    def chain_verify(self, certificate: Certificate | dict,
                     chain: list[Certificate | dict]) -> bool:
        """Verify a certificate chain against the root CA (public endpoint).

        Args:
            certificate: Leaf certificate to verify.
            chain:       Ordered list of intermediate CAs (leaf's issuer first).

        Returns:
            True if valid.
        """
        cert_dict = certificate.raw if isinstance(certificate, Certificate) else certificate
        chain_dicts = [c.raw if isinstance(c, Certificate) else c for c in chain]
        d = self._http.post("/ca/chain-verify", {
            "certificate": cert_dict,
            "chain":       chain_dicts,
        })
        return d.get("valid", False)


class _HealthClient:
    def __init__(self, http: _HTTP) -> None:
        self._http = http

    def status(self) -> HealthStatus:
        """GET / — server health and algorithm info."""
        d = self._http.get("/")
        return HealthStatus.from_dict(d)

    def live(self) -> bool:
        """GET /health/live — True if the server is alive."""
        try:
            self._http.get("/health/live")
            return True
        except Exception:
            return False

    def ready(self) -> dict:
        """GET /health/ready — readiness probe with FIPS status."""
        return self._http.get("/health/ready")

    def fips(self) -> FIPSReport:
        """GET /health/fips — full FIPS compliance report."""
        d = self._http.get("/health/fips")
        return FIPSReport.from_dict(d)


# ── Main client ────────────────────────────────────────────────────────────────

class QuantumShield:
    """Synchronous QuantumShield client.

    All sub-clients share one underlying HTTP connection and JWT token.
    Call :meth:`auth` once to authenticate; the token is automatically
    included in all subsequent requests.

    Args:
        base_url:         Server URL, e.g. ``"https://qs.example.com"``.
        token:            Pre-issued QST token (skip if calling :meth:`auth`).
        bootstrap_secret: Server bootstrap secret for token issuance.
        timeout:          HTTP request timeout in seconds (default 30).
        verify_ssl:       Set ``False`` to skip TLS verification (dev only).

    Example::

        qs = QuantumShield("http://localhost:8080")
        qs.auth("alice", ["read", "write"], bootstrap_secret="my-secret")

        key = qs.keys.generate("ML-KEM-768")
        enc = qs.crypto.encrypt(key.key_id, b"secret data")
        dec = qs.crypto.decrypt(key.key_id, enc.encrypted)
        print(dec.plaintext)  # b"secret data"
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
        self._http = _HTTP(base_url, timeout, verify_ssl)
        self._bootstrap_secret = bootstrap_secret
        if token:
            self._http._token = token

        self.health  = _HealthClient(self._http)
        self.auth_   = _AuthClient(self._http)
        self.keys    = _KeysClient(self._http)
        self.crypto  = _CryptoClient(self._http)
        self.kdf     = _KDFClient(self._http)
        self.ca      = _CAClient(self._http)

    def auth(self, user_id: str, roles: list[str],
             bootstrap_secret: str | None = None) -> Token:
        """Issue a token and configure it for all subsequent requests.

        Args:
            user_id:          User or service identifier.
            roles:            Permission list: ``"read"``, ``"write"``, ``"admin"``.
            bootstrap_secret: Overrides the one passed to the constructor.

        Returns:
            :class:`Token` (also stored internally for future requests).
        """
        secret = bootstrap_secret or self._bootstrap_secret
        return self.auth_.issue(user_id, roles, bootstrap_secret=secret)

    @property
    def token(self) -> str | None:
        """Currently active bearer token."""
        return self._http._token

    @token.setter
    def token(self, value: str | None) -> None:
        self._http._token = value

    def __repr__(self) -> str:
        return f"QuantumShield(base_url={self._http._base!r})"
