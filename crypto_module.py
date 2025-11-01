from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64, os, json
from datetime import datetime, timezone

data = b"secret data to transmit"

def create_key_json(path="Settings\\crypto_config.json"):
    key = get_random_bytes(32)  # AES-256
    payload = {
        "kty": "oct",
        "kid": "aes-key-1",
        "alg": "A256CTR",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "k_b64": "2V+g5JR25rPIfIACu/iKm0iW+D22UKctxKmicmX8DLU="
    }
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return key

def load_key_from_json(path="Settings\\crypto_config.json") -> bytes:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    return base64.b64decode(payload["k_b64"])

def encrypt(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.encrypt(data)
    return ct, cipher.nonce

def decrypt(ct: bytes, nonce: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    return cipher.decrypt(ct)

# Inicjalizacja klucza
if not os.path.exists("Settings\\crypto_config.json"):
    aes_key = create_key_json()
else:
    aes_key = load_key_from_json()