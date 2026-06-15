"""
AES-256-GCM encryption para findings con sensitivity=HIGH.
Guardarraíl constitucional AEGIS §3.6.
"""
import base64
import hashlib
import os
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


def _get_key() -> bytes:
    """
    Deriva clave AES-256 desde AEGIS_ENCRYPTION_KEY (secreto dedicado — separado de AEGIS_API_KEY).
    FIX P1: clave de cifrado independiente de la clave de autenticación.
    Generar con: openssl rand -base64 32  → añadir a Secret Manager como AEGIS_ENCRYPTION_KEY.
    """
    raw = os.environ.get("AEGIS_ENCRYPTION_KEY", "")
    if not raw:
        raise RuntimeError(
            "AEGIS_ENCRYPTION_KEY no configurado. "
            "Genera con 'openssl rand -base64 32' y añade a Secret Manager."
        )
    try:
        key = base64.b64decode(raw)
    except Exception:
        key = hashlib.sha256(raw.encode()).digest()
    if len(key) not in (16, 24, 32):
        raise RuntimeError(f"AEGIS_ENCRYPTION_KEY debe ser 16/24/32 bytes tras decodificar. Recibido: {len(key)}.")
    return key


def encrypt_high(plaintext: str) -> str:
    """
    Cifra texto con AES-256-GCM.
    Retorna 'aegis:v1:<nonce_b64>:<ciphertext_b64>'.
    """
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("Instala cryptography>=41.0.0 para cifrar datos HIGH.")
    key   = _get_key()
    nonce = os.urandom(12)  # 96-bit nonce para GCM
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return f"aegis:v1:{base64.b64encode(nonce).decode()}:{base64.b64encode(ct).decode()}"


def decrypt_high(ciphertext: str) -> str:
    """Descifra un valor producido por encrypt_high()."""
    if not _HAS_CRYPTOGRAPHY:
        raise RuntimeError("Instala cryptography>=41.0.0 para descifrar datos HIGH.")
    parts = ciphertext.split(":")
    if len(parts) != 4 or parts[0] != "aegis" or parts[1] != "v1":
        raise ValueError(f"Formato inválido. Esperado 'aegis:v1:<nonce>:<ct>', recibido: {ciphertext[:30]}")
    nonce = base64.b64decode(parts[2])
    ct    = base64.b64decode(parts[3])
    key   = _get_key()
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()


def maybe_encrypt(value: str, sensitivity: str) -> str:
    """Cifra si sensitivity='HIGH', devuelve tal cual en caso contrario."""
    if sensitivity == "HIGH":
        return encrypt_high(value)
    return value


def is_encrypted(value: str) -> bool:
    return isinstance(value, str) and value.startswith("aegis:v1:")
