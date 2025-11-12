import base64 # importowanie modułu base64 do kodowania i dekodowania danych w formacie base64
import hashlib # importowanie modułu hashlib do tworzenia skrótów kryptograficznych
import os # importowanie modułu os do interakcji z systemem operacyjnym
from pathlib import Path # importowanie klasy Path z modułu pathlib do obsługi ścieżek plików

from Crypto.Cipher import AES # importowanie klasy AES z modułu Crypto.Cipher do szyfrowania i deszyfrowania danych

from .encrypt import ( # importowanie stałych i funkcji z pliku encrypt.py
    KEY_FILE,
    _DEFAULT_LOGIN_SECRET,
    _ensure_json_key,
    _ensure_user_secret_key,
)


def _aes_decrypt(token: str, key: bytes) -> bytes: #funkcja do odszyfrowywania danych za pomocą AES
    """Odwrotność funkcji :func:`security.encrypt._aes_encrypt`."""

    raw = base64.b64decode(token.encode("ascii")) #dekodowanie danych z formatu base64
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:] #wydzielenie nonce, tagu i zaszyfrowanego tekstu
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce) #utworzenie obiektu szyfrującego AES w trybie EAX
    return cipher.decrypt_and_verify(ciphertext, tag) #odszyfrowanie i weryfikacja danych


def decrypt_login_credentials( #odszyfrowuje wartości z encrypt.encrypt_login_credentials
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


def decrypt_with_json_key( #odszyfrowuje dane zabezpieczone kluczem JSON
    token: str,
    *,
    key_file: str | Path | None = None,
) -> bytes:
    """Odszyfrowuje dane z ``encrypt.encrypt_with_json_key``."""

    key_path = Path(key_file) if key_file is not None else KEY_FILE
    key = _ensure_json_key(key_path, create=False)
    return _aes_decrypt(token, key)


def decrypt_with_user_secret(token: str, secret: str | bytes) -> bytes: #odszyfrowuje dane zabezpieczone hasłem zalogowanego użytkownika
    """Odszyfrowuje dane zabezpieczone hasłem zalogowanego użytkownika."""

    key = _ensure_user_secret_key(secret) #uzyskanie klucza użytkownika
    return _aes_decrypt(token, key) #odszyfrowanie danych
