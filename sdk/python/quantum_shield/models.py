"""QuantumShield SDK — response / request dataclasses."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


# ── Token ──────────────────────────────────────────────────────────────────────

@dataclass
class Token:
    """Quantum Secure Token (QST) returned by /auth/token."""
    token:      str
    user_id:    str
    roles:      list[str]
    expires_at: datetime | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "Token":
        exp = d.get("expires_at")
        return cls(
            token=d["token"],
            user_id=d.get("user_id", ""),
            roles=d.get("roles", []),
            expires_at=datetime.fromisoformat(exp) if exp else None,
        )


# ── Keys ───────────────────────────────────────────────────────────────────────

@dataclass
class KeyPair:
    """ML-KEM keypair returned by /keys/generate."""
    key_id:          str
    public_key:      str          # base64
    algorithm:       str          # "ML-KEM-768" | "ML-KEM-1024"
    public_key_size: int
    vault_shards:    int
    vault_threshold: int

    @classmethod
    def from_dict(cls, d: dict) -> "KeyPair":
        return cls(
            key_id=d["key_id"],
            public_key=d["public_key"],
            algorithm=d.get("algorithm", "ML-KEM-768"),
            public_key_size=d.get("public_key_size", 0),
            vault_shards=d.get("vault_shards", 0),
            vault_threshold=d.get("vault_threshold", 0),
        )


@dataclass
class PublicKey:
    """Public encapsulation key from /keys/{id}/public."""
    key_id:     str
    public_key: str   # base64

    @classmethod
    def from_dict(cls, d: dict) -> "PublicKey":
        return cls(key_id=d["key_id"], public_key=d["public_key"])


# ── Encryption ─────────────────────────────────────────────────────────────────

@dataclass
class Encrypted:
    """Nested encrypted object as returned by /encrypt."""
    kem_ciphertext: str   # base64
    nonce:          str   # base64
    data:           str   # base64
    created_at:     int   # Unix timestamp (bound into AEAD tag)

    @classmethod
    def from_dict(cls, d: dict) -> "Encrypted":
        return cls(
            kem_ciphertext=d["kem_ciphertext"],
            nonce=d["nonce"],
            data=d["data"],
            created_at=d["created_at"],
        )

    def to_dict(self) -> dict:
        return {
            "kem_ciphertext": self.kem_ciphertext,
            "nonce":          self.nonce,
            "data":           self.data,
            "created_at":     self.created_at,
        }


@dataclass
class EncryptResult:
    """Full response from /encrypt."""
    encrypted:    Encrypted
    algorithm:    str
    quantum_safe: bool

    @classmethod
    def from_dict(cls, d: dict) -> "EncryptResult":
        return cls(
            encrypted=Encrypted.from_dict(d["encrypted"]),
            algorithm=d.get("algorithm", ""),
            quantum_safe=d.get("quantum_safe", True),
        )


@dataclass
class DecryptResult:
    """Response from /decrypt."""
    plaintext: bytes   # decoded from base64

    @classmethod
    def from_dict(cls, d: dict) -> "DecryptResult":
        import base64
        return cls(plaintext=base64.b64decode(d["plaintext"]))


# ── Signatures ─────────────────────────────────────────────────────────────────

@dataclass
class Signature:
    """Response from /sign or /slh-dsa/sign."""
    signature:  str   # base64
    public_key: str   # base64
    algorithm:  str
    message:    str   # base64

    @classmethod
    def from_dict(cls, d: dict) -> "Signature":
        return cls(
            signature=d["signature"],
            public_key=d.get("public_key", ""),
            algorithm=d.get("algorithm", ""),
            message=d.get("message", ""),
        )


@dataclass
class VerifyResult:
    """Response from /verify-signature."""
    valid:   bool
    message: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "VerifyResult":
        return cls(valid=d.get("valid", False), message=d.get("message", ""))


# ── CA ─────────────────────────────────────────────────────────────────────────

@dataclass
class Certificate:
    """Post-quantum ML-DSA-87 certificate."""
    version:        int
    serial:         str
    subject:        str
    issuer:         str
    algorithm:      str
    public_key:     str
    public_key_type: str
    not_before:     str
    not_after:      str
    is_ca:          bool
    signature:      str
    raw:            dict = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, d: dict) -> "Certificate":
        return cls(
            version=d.get("version", 1),
            serial=d.get("serial", ""),
            subject=d.get("subject", ""),
            issuer=d.get("issuer", ""),
            algorithm=d.get("algorithm", "ML-DSA-87"),
            public_key=d.get("public_key", ""),
            public_key_type=d.get("public_key_type", ""),
            not_before=d.get("not_before", ""),
            not_after=d.get("not_after", ""),
            is_ca=d.get("is_ca", False),
            signature=d.get("signature", ""),
            raw=d,
        )


@dataclass
class CAInitResult:
    """Response from POST /ca/init."""
    certificate: Certificate
    message:     str

    @classmethod
    def from_dict(cls, d: dict) -> "CAInitResult":
        return cls(
            certificate=Certificate.from_dict(d.get("certificate", {})),
            message=d.get("message", ""),
        )


@dataclass
class CertVerifyResult:
    """Response from POST /ca/verify."""
    valid:   bool
    error:   str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "CertVerifyResult":
        return cls(valid=d.get("valid", False), error=d.get("error", ""))


# ── KDF ────────────────────────────────────────────────────────────────────────

@dataclass
class DerivedKey:
    """Response from /kdf/hkdf or /kdf/argon2."""
    key:       str   # base64
    algorithm: str
    key_size:  int

    @classmethod
    def from_dict(cls, d: dict) -> "DerivedKey":
        return cls(
            key=d.get("key", ""),
            algorithm=d.get("algorithm", ""),
            key_size=d.get("key_size", 0),
        )


# ── Health ─────────────────────────────────────────────────────────────────────

@dataclass
class HealthStatus:
    """Response from GET /."""
    status:     str
    algorithms: dict[str, Any]
    version:    str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "HealthStatus":
        return cls(
            status=d.get("status", ""),
            algorithms=d.get("algorithms", {}),
            version=d.get("version", ""),
        )


@dataclass
class FIPSReport:
    """Response from GET /health/fips."""
    overall:    str
    probes:     list[dict]
    timestamp:  str
    go_version: str

    @classmethod
    def from_dict(cls, d: dict) -> "FIPSReport":
        return cls(
            overall=d.get("overall", ""),
            probes=d.get("probes", []),
            timestamp=d.get("timestamp", ""),
            go_version=d.get("go_version", ""),
        )
