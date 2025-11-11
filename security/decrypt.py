"""Proste pomocnicze funkcje AES do odszyfrowywania haseł i danych."""

import base64
import hashlib
import os
from pathlib import Path

from Crypto.Cipher import AES

from .encrypt import (
    KEY_FILE,
    _DEFAULT_LOGIN_SECRET,
    _ensure_json_key,
    _ensure_user_secret_key,
)


def _aes_decrypt(token: str, key: bytes) -> bytes:
    """Odwrotność funkcji :func:`security.encrypt._aes_encrypt`."""

    raw = base64.b64decode(token.encode("ascii"))
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def decrypt_login_credentials(
    encrypted_login: str,
    encrypted_password: str,
    *,
    pepper: str | None = None,
) -> dict[str, str]:
    """Odszyfrowuje wartości z ``encrypt.encrypt_login_credentials``."""

    secret = pepper or os.getenv("LOGIN_ENCRYPTION_SECRET") or _DEFAULT_LOGIN_SECRET
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    return {
        "login": _aes_decrypt(encrypted_login, key).decode("utf-8"),
        "password": _aes_decrypt(encrypted_password, key).decode("utf-8"),
    }


def decrypt_with_json_key(
    token: str,
    *,
    key_file: str | Path | None = None,
) -> bytes:
    """Odszyfrowuje dane z ``encrypt.encrypt_with_json_key``."""

    key_path = Path(key_file) if key_file is not None else KEY_FILE
    key = _ensure_json_key(key_path, create=False)
    return _aes_decrypt(token, key)


def decrypt_with_user_secret(token: str, secret: str | bytes) -> bytes:
    """Odszyfrowuje dane zabezpieczone hasłem zalogowanego użytkownika."""

    key = _ensure_user_secret_key(secret)
    return _aes_decrypt(token, key)
