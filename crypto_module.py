# crypto_module.py
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64, os, json
from datetime import datetime, timezone


def create_key_json(path="Settings\\crypto_config.json") -> bytes:
    """Generuje nowy klucz AES-256 i zapisuje go do JSON."""
    key = get_random_bytes(32)  # AES-256
    k_b64 = base64.b64encode(key).decode("ascii") 
    payload = {
        "kty": "oct",
        "kid": "aes-key-1",
        "alg": "A256CTR",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "k_b64": k_b64 
    }

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    return key


def load_key_from_json(path="Settings\\crypto_config.json") -> bytes:
    """Wczytuje klucz AES z pliku JSON."""
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return base64.b64decode(payload["k_b64"])


def get_aes_key(path="Settings\\crypto_config.json") -> bytes:
    """Zwraca klucz AES, tworzy nowy jeśli nie istnieje."""
    if not os.path.exists(path):
        return create_key_json(path)
    return load_key_from_json(path)


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Szyfruje dane bajtowe (AES-256-CTR)."""
    cipher = AES.new(key, AES.MODE_CTR)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext, cipher.nonce


def decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """Odszyfrowuje dane bajtowe (AES-256-CTR)."""
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext