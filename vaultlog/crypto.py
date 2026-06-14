from __future__ import annotations

import base64
import json
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


@dataclass(slots=True)
class EncryptedPayload:
    version: int
    nonce: str
    ciphertext: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EncryptedPayload":
        return cls(
            version=int(payload["version"]),
            nonce=str(payload["nonce"]),
            ciphertext=str(payload["ciphertext"]),
        )


def encrypt_bytes(key: bytes, plaintext: bytes) -> EncryptedPayload:
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return EncryptedPayload(
        version=1,
        nonce=_b64encode(nonce),
        ciphertext=_b64encode(ciphertext),
    )


def decrypt_bytes(key: bytes, payload: EncryptedPayload) -> bytes:
    if payload.version != 1:
        raise ValueError(f"Unsupported payload version: {payload.version}")
    nonce = _b64decode(payload.nonce)
    ciphertext = _b64decode(payload.ciphertext)
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def encrypt_json(key: bytes, document: dict[str, Any]) -> dict[str, Any]:
    plaintext = json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8")
    return encrypt_bytes(key, plaintext).to_dict()


def decrypt_json(key: bytes, document: dict[str, Any]) -> dict[str, Any]:
    plaintext = decrypt_bytes(key, EncryptedPayload.from_dict(document))
    return json.loads(plaintext.decode("utf-8"))
