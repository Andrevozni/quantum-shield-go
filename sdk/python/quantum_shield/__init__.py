"""QuantumShield Python SDK — post-quantum cryptography client.

Quick start::

    from quantum_shield import QuantumShield

    qs = QuantumShield("http://localhost:8080")
    qs.auth("alice", ["read", "write"], bootstrap_secret="my-secret")

    # Generate a post-quantum keypair (ML-KEM-768, NIST FIPS 203)
    key = qs.keys.generate()

    # Encrypt (ML-KEM-768 + AES-256-GCM)
    enc = qs.crypto.encrypt(key.key_id, b"secret message")

    # Decrypt
    dec = qs.crypto.decrypt(key.key_id, enc.encrypted)
    assert dec.plaintext == b"secret message"

    # Sign (ML-DSA-65, NIST FIPS 204)
    sig = qs.crypto.sign(key.key_id, b"document")

    # Verify
    result = qs.crypto.verify_signature(b"document", sig.signature, sig.public_key)
    assert result.valid

Async usage::

    from quantum_shield.async_client import AsyncQuantumShield

    async with AsyncQuantumShield("http://localhost:8080") as qs:
        await qs.auth("alice", ["write"])
        key = await qs.keys.generate()
        ...
"""
from .client import QuantumShield
from .exceptions import (
    AuthenticationError,
    AuthorizationError,
    CANotInitialisedError,
    CertificateVerificationError,
    NotFoundError,
    QuantumShieldError,
    RateLimitError,
    ReplayError,
    ServerError,
    ValidationError,
)
from .models import (
    CAInitResult,
    Certificate,
    CertVerifyResult,
    DecryptResult,
    DerivedKey,
    Encrypted,
    EncryptResult,
    FIPSReport,
    HealthStatus,
    KeyPair,
    PublicKey,
    Signature,
    Token,
    VerifyResult,
)

__version__ = "0.1.0"
__all__ = [
    "QuantumShield",
    # Exceptions
    "QuantumShieldError",
    "AuthenticationError",
    "AuthorizationError",
    "CANotInitialisedError",
    "CertificateVerificationError",
    "NotFoundError",
    "QuantumShieldError",
    "RateLimitError",
    "ReplayError",
    "ServerError",
    "ValidationError",
    # Models
    "CAInitResult",
    "Certificate",
    "CertVerifyResult",
    "DecryptResult",
    "DerivedKey",
    "Encrypted",
    "EncryptResult",
    "FIPSReport",
    "HealthStatus",
    "KeyPair",
    "PublicKey",
    "Signature",
    "Token",
    "VerifyResult",
]
