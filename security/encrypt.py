"""Proste pomocnicze funkcje AES do szyfrowania haseł i danych."""

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Union

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY_FILE = (Path(__file__).resolve().parent.parent / "config" / "key.json").resolve()
_DEFAULT_LOGIN_SECRET = "PASSWORD_MANAGER_LOGIN_SECRET"


def _ensure_json_key(path: Path = KEY_FILE, *, create: bool = False) -> bytes:
    """Zwraca 32-bajtowy klucz AES przechowywany w ``config/key.json``."""

    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        return base64.b64decode(data["key"])

    if not create:
        raise FileNotFoundError(
            "Nie znaleziono pliku z kluczem aplikacji. Sprawdź config/key.json."
        )

    key = get_random_bytes(32)
    payload = {"key": base64.b64encode(key).decode("ascii")}
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return key


def _aes_encrypt(raw: bytes, key: bytes) -> str:
    """Szyfruje ``raw`` w trybie AES-EAX i zwraca tekst w base64."""

    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(raw)
    blob = cipher.nonce + tag + ciphertext
    return base64.b64encode(blob).decode("ascii")


def encrypt_login_credentials(
    login: str,
    password: str,
    *,
    pepper: str | None = None,
) -> dict[str, str]:
    """Szyfruje dane logowania użytkowników bazy danych."""

    secret = pepper or os.getenv("LOGIN_ENCRYPTION_SECRET") or _DEFAULT_LOGIN_SECRET
    key = hashlib.sha256(secret.encode("utf-8")).digest()
    return {
        "login": _aes_encrypt(login.encode("utf-8"), key),
        "password": _aes_encrypt(password.encode("utf-8"), key),
    }


def _ensure_user_secret_key(secret: Union[str, bytes]) -> bytes:
    """Wyprowadza 32-bajtowy klucz z podanego hasła użytkownika."""

    if isinstance(secret, str):
        secret_bytes = secret.encode("utf-8")
    else:
        secret_bytes = secret
    return hashlib.sha256(secret_bytes).digest()


def encrypt_with_json_key(
    data: Union[str, bytes],
    *,
    key_file: str | os.PathLike[str] | None = None,
) -> str:
    """Szyfruje dowolne dane przy użyciu klucza zapisanego obok modułu."""

    payload = data.encode("utf-8") if isinstance(data, str) else data
    key_path = Path(key_file) if key_file is not None else KEY_FILE
    key = _ensure_json_key(key_path, create=False)
    return _aes_encrypt(payload, key)


def encrypt_with_user_secret(
    data: Union[str, bytes],
    secret: Union[str, bytes],
) -> str:
    """Szyfruje ``data`` wykorzystując hasło zalogowanego użytkownika jako klucz."""

    payload = data.encode("utf-8") if isinstance(data, str) else data
    key = _ensure_user_secret_key(secret)
    return _aes_encrypt(payload, key)
