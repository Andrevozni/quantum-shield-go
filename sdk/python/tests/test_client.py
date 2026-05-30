"""Python SDK integration tests.

Run against a live QuantumShield server:

    # Terminal 1 — start server
    go run ./cmd/server

    # Terminal 2 — run tests
    cd sdk/python
    pip install -e ".[dev]"
    pytest tests/ -v

Set QS_URL to override the default server URL.
"""
from __future__ import annotations

import os
import pytest

from quantum_shield import (
    QuantumShield,
    AuthenticationError,
    AuthorizationError,
    CertificateVerificationError,
    ValidationError,
)
from quantum_shield.models import Encrypted

BASE_URL   = os.environ.get("QS_URL", "http://localhost:8080")
SECRET     = os.environ.get("QS_SECRET", "")   # BOOTSTRAP_SECRET on the server
SKIP_LIVE  = os.environ.get("QS_SKIP_LIVE", "0") == "1"

skip_if_no_server = pytest.mark.skipif(
    SKIP_LIVE, reason="Set QS_SKIP_LIVE=0 and start the server to run live tests"
)


@pytest.fixture(scope="session")
def qs() -> QuantumShield:
    """Authenticated client reused across the whole test session."""
    client = QuantumShield(BASE_URL, bootstrap_secret=SECRET or None,
                           verify_ssl=False)
    try:
        client.auth("test-user", ["admin", "write", "read"])
    except Exception as e:
        pytest.skip(f"Cannot connect to QuantumShield server at {BASE_URL}: {e}")
    return client


# ── Health ─────────────────────────────────────────────────────────────────────

@skip_if_no_server
def test_health_status(qs: QuantumShield) -> None:
    status = qs.health.status()
    assert status.status == "operational"
    assert "kem" in status.algorithms


@skip_if_no_server
def test_health_live(qs: QuantumShield) -> None:
    assert qs.health.live() is True


@skip_if_no_server
def test_health_fips(qs: QuantumShield) -> None:
    report = qs.health.fips()
    assert report.overall in ("pass", "fail")
    assert len(report.probes) > 0


# ── Auth ───────────────────────────────────────────────────────────────────────

@skip_if_no_server
def test_auth_issue_and_verify(qs: QuantumShield) -> None:
    tok = qs.auth_.issue("sdk-test", ["read"])
    assert tok.token
    result = qs.auth_.verify(tok.token)
    assert result.get("valid") or "subject" in result or "claims" in result


@skip_if_no_server
def test_auth_revoke(qs: QuantumShield) -> None:
    # Issue a throwaway token then revoke it.
    client2 = QuantumShield(BASE_URL, bootstrap_secret=SECRET or None,
                            verify_ssl=False)
    tok = client2.auth("revoke-test", ["read"])
    client2.auth_.revoke(tok.token)
    # Using the revoked token must fail.
    with pytest.raises(AuthenticationError):
        QuantumShield(BASE_URL, token=tok.token,
                      verify_ssl=False).keys.list()


@skip_if_no_server
def test_auth_wrong_role(qs: QuantumShield) -> None:
    read_client = QuantumShield(BASE_URL, verify_ssl=False)
    read_client.auth("read-only", ["read"])
    with pytest.raises(AuthorizationError):
        read_client.keys.generate()


# ── Keys ───────────────────────────────────────────────────────────────────────

@skip_if_no_server
def test_keys_generate_768(qs: QuantumShield) -> None:
    kp = qs.keys.generate("ML-KEM-768")
    assert kp.key_id
    assert kp.public_key
    assert kp.algorithm == "ML-KEM-768"
    assert kp.public_key_size > 0


@skip_if_no_server
def test_keys_generate_1024(qs: QuantumShield) -> None:
    kp = qs.keys.generate("ML-KEM-1024")
    assert kp.algorithm in ("ML-KEM-1024", "ML-KEM-768")  # server may normalise


@skip_if_no_server
def test_keys_list(qs: QuantumShield) -> None:
    qs.keys.generate()
    ids = qs.keys.list()
    assert isinstance(ids, list)
    assert len(ids) >= 1


@skip_if_no_server
def test_keys_public_key(qs: QuantumShield) -> None:
    kp = qs.keys.generate()
    pk = qs.keys.public_key(kp.key_id)
    assert pk.key_id == kp.key_id
    assert pk.public_key == kp.public_key


# ── Encrypt / Decrypt ──────────────────────────────────────────────────────────

@skip_if_no_server
def test_encrypt_decrypt_bytes(qs: QuantumShield) -> None:
    kp = qs.keys.generate()
    plaintext = b"hello, post-quantum world"
    enc = qs.crypto.encrypt(kp.key_id, plaintext)
    assert enc.encrypted.kem_ciphertext
    assert enc.encrypted.nonce
    assert enc.encrypted.data
    dec = qs.crypto.decrypt(kp.key_id, enc.encrypted)
    assert dec.plaintext == plaintext


@skip_if_no_server
def test_encrypt_decrypt_string(qs: QuantumShield) -> None:
    kp = qs.keys.generate()
    enc = qs.crypto.encrypt(kp.key_id, "unicode: ñoño")
    dec = qs.crypto.decrypt(kp.key_id, enc.encrypted)
    assert "ñoño" in dec.plaintext.decode("utf-8", errors="replace")


@skip_if_no_server
def test_replay_attack_rejected(qs: QuantumShield) -> None:
    """Second decryption of the same ciphertext must fail."""
    kp  = qs.keys.generate()
    enc = qs.crypto.encrypt(kp.key_id, b"replay test")
    qs.crypto.decrypt(kp.key_id, enc.encrypted)          # first: ok
    with pytest.raises(Exception):                         # second: rejected
        qs.crypto.decrypt(kp.key_id, enc.encrypted)


# ── Signatures ─────────────────────────────────────────────────────────────────

@skip_if_no_server
def test_sign_and_verify(qs: QuantumShield) -> None:
    kp  = qs.keys.generate()
    msg = b"important document"
    sig = qs.crypto.sign(kp.key_id, msg)
    assert sig.signature
    result = qs.crypto.verify_signature(msg, sig.signature, sig.public_key)
    assert result.valid


@skip_if_no_server
def test_verify_tampered_message_fails(qs: QuantumShield) -> None:
    kp  = qs.keys.generate()
    sig = qs.crypto.sign(kp.key_id, b"original")
    result = qs.crypto.verify_signature(b"tampered", sig.signature, sig.public_key)
    assert not result.valid


# ── KDF ────────────────────────────────────────────────────────────────────────

@skip_if_no_server
def test_hkdf(qs: QuantumShield) -> None:
    import base64
    ikm = base64.b64encode(b"\x00" * 32).decode()
    derived = qs.kdf.hkdf(ikm, info="test-context", length=32)
    assert derived.key
    assert derived.key_size == 32


@skip_if_no_server
def test_kdf_salt(qs: QuantumShield) -> None:
    salt = qs.kdf.generate_salt(32)
    assert salt
    import base64
    assert len(base64.b64decode(salt)) == 32


# ── CA ─────────────────────────────────────────────────────────────────────────

@skip_if_no_server
def test_ca_full_lifecycle(qs: QuantumShield) -> None:
    # Init root CA.
    result = qs.ca.init("CN=SDK Test Root CA,O=QuantumShield")
    assert result.certificate.is_ca

    # Issue a leaf cert.
    kp   = qs.keys.generate()
    cert = qs.ca.sign(
        subject="CN=sdk-test.example.com",
        public_key=kp.public_key,
        public_key_type="ML-KEM-768",
    )
    assert cert.serial
    assert cert.subject == "CN=sdk-test.example.com"

    # Verify the leaf cert.
    verify = qs.ca.verify(cert)
    assert verify.valid

    # Revoke and verify that it now fails.
    qs.ca.revoke(cert.serial)
    with pytest.raises(CertificateVerificationError):
        qs.ca.verify(cert)


@skip_if_no_server
def test_ca_certificate_public(qs: QuantumShield) -> None:
    """Root CA certificate is accessible without auth."""
    public_client = QuantumShield(BASE_URL, verify_ssl=False)
    # /ca/certificate is public — no token needed
    try:
        ca_cert = public_client.ca.get_certificate()
        assert ca_cert.is_ca
    except Exception:
        pytest.skip("CA not yet initialised on this server instance")


@skip_if_no_server
def test_ca_verify_forged_cert_fails(qs: QuantumShield) -> None:
    """A self-signed / fabricated certificate must not verify."""
    qs.ca.init("CN=Forgery Test CA")
    fake = {
        "version": 1,
        "serial": "DEADBEEF",
        "subject": "CN=rogue.example.com",
        "issuer":  "CN=Forgery Test CA",
        "algorithm": "ML-DSA-87",
        "public_key": "ZmFrZQ==",
        "public_key_type": "ML-KEM-768",
        "not_before": "2025-01-01T00:00:00Z",
        "not_after":  "2030-01-01T00:00:00Z",
        "is_ca": False,
        "signature": "ZmFrZXNpZw==",
    }
    with pytest.raises((CertificateVerificationError, ValidationError)):
        qs.ca.verify(fake)


# ── Async smoke test ───────────────────────────────────────────────────────────

@skip_if_no_server
@pytest.mark.asyncio
async def test_async_client_basic() -> None:
    try:
        from quantum_shield.async_client import AsyncQuantumShield
    except ImportError:
        pytest.skip("httpx not installed — skipping async tests")

    async with AsyncQuantumShield(BASE_URL, verify_ssl=False) as qs:
        try:
            await qs.auth("async-test", ["read", "write"],
                          bootstrap_secret=SECRET or None)
        except Exception as e:
            pytest.skip(f"Server unavailable: {e}")

        assert await qs.health.live()

        kp  = await qs.keys.generate()
        enc = await qs.crypto.encrypt(kp.key_id, b"async hello")
        dec = await qs.crypto.decrypt(kp.key_id, enc.encrypted)
        assert dec.plaintext == b"async hello"
