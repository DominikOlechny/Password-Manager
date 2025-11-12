"""Proste pomocnicze funkcje AES do szyfrowania haseł i danych."""

import base64 # importowanie modułu base64 do kodowania i dekodowania danych w formacie base64
import hashlib # importowanie modułu hashlib do tworzenia skrótów kryptograficznych
import json # importowanie modułu json do obsługi plików JSON
import os # importowanie modułu os do interakcji z systemem operacyjnym
from pathlib import Path # importowanie klasy Path z modułu pathlib do obsługi ścieżek plików
from typing import Union # importowanie typu Union z modułu typing do definiowania typów zmiennych

from Crypto.Cipher import AES # importowanie klasy AES z modułu Crypto.Cipher do szyfrowania i deszyfrowania danych
from Crypto.Random import get_random_bytes # importowanie funkcji get_random_bytes z modułu Crypto.Random do generowania losowych bajtów

KEY_FILE = (Path(__file__).resolve().parent.parent / "config" / "key.json").resolve() # ścieżka do pliku z kluczem szyfrowania
_DEFAULT_LOGIN_SECRET = "PASSWORD_MANAGER_LOGIN_SECRET" # domyślny sekret do szyfrowania danych logowania


def _ensure_json_key(path: Path = KEY_FILE, *, create: bool = False) -> bytes: #    funkcja do zapewnienia istnienia klucza JSON
    """Zwraca 32-bajtowy klucz AES przechowywany w ``config/key.json``."""

    if path.exists(): #jeżeli plik z kluczem istnieje to odczytaj klucz
        data = json.loads(path.read_text(encoding="utf-8")) #odczytanie zawartości pliku JSON
        return base64.b64decode(data["key"]) #zwróć klucz odszyfrowany z formatu base64

    if not create: #jeżeli plik z kluczem nie istnieje i nie należy go tworzyć to zgłoś błąd
        raise FileNotFoundError( 
            "Nie znaleziono pliku z kluczem aplikacji. Sprawdź config/key.json."
        )

    key = get_random_bytes(32) #wygenerowanie nowego losowego klucza AES
    payload = {"key": base64.b64encode(key).decode("ascii")} #przygotowanie danych do zapisania w pliku JSON
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8") #zapisanie klucza do pliku JSON
    return key #zwrócenie wygenerowanego klucza


def _aes_encrypt(raw: bytes, key: bytes) -> str: #funkcja do szyfrowania danych za pomocą AES
    """Szyfruje ``raw`` w trybie AES-EAX i zwraca tekst w base64.""" 

    cipher = AES.new(key, AES.MODE_EAX) #utworzenie obiektu szyfrującego AES w trybie EAX
    ciphertext, tag = cipher.encrypt_and_digest(raw) #szyfrowanie danych i wygenerowanie tagu uwierzytelniającego
    blob = cipher.nonce + tag + ciphertext #łączenie nonce, tagu i zaszyfrowanego tekstu w jeden ciąg bajtów
    return base64.b64encode(blob).decode("ascii") #zakodowanie zaszyfrowanych danych w formacie base64 i zwrócenie jako string


def encrypt_login_credentials( #szyfruje dane logowania użytkowników bazy danych
    login: str, #login użytkownika
    password: str, #hasło użytkownika
    *, 
    pepper: str | None = None, #dodatkowy sekret do szyfrowania
) -> dict[str, str]:
    """Szyfruje dane logowania użytkowników bazy danych."""

    secret = pepper or os.getenv("LOGIN_ENCRYPTION_SECRET") or _DEFAULT_LOGIN_SECRET #uzyskanie sekretu do szyfrowania
    key = hashlib.sha256(secret.encode("utf-8")).digest() #wyprowadzenie 32-bajtowego klucza z sekretu
    return { #zwrócenie zaszyfrowanych danych logowania
        "login": _aes_encrypt(login.encode("utf-8"), key),
        "password": _aes_encrypt(password.encode("utf-8"), key),
    }


def _ensure_user_secret_key(secret: Union[str, bytes]) -> bytes: #funkcja do zapewnienia istnienia klucza użytkownika
    """Wyprowadza 32-bajtowy klucz z podanego hasła użytkownika.""" 

    if isinstance(secret, str): #jeżeli sekret jest stringiem to zakoduj go na bajty
        secret_bytes = secret.encode("utf-8") #zakodowanie sekretu na bajty
    else: #jeżeli sekret jest już bajtami to użyj go bez zmian
        secret_bytes = secret
    return hashlib.sha256(secret_bytes).digest() #wyprowadzenie 32-bajtowego klucza z sekretu


def encrypt_with_json_key( #szyfruje dowolne dane przy użyciu klucza zapisanego obok modułu
    data: Union[str, bytes], # dane do zaszyfrowania
    *,
    key_file: str | os.PathLike[str] | None = None, #ścieżka do pliku z kluczem
) -> str:
    """Szyfruje dowolne dane przy użyciu klucza zapisanego obok modułu."""

    payload = data.encode("utf-8") if isinstance(data, str) else data #konwersja danych na bajty jeżeli są w formie stringa
    key_path = Path(key_file) if key_file is not None else KEY_FILE #ustalenie ścieżki do pliku z kluczem
    key = _ensure_json_key(key_path, create=False) #uzyskanie klucza z pliku JSON
    return _aes_encrypt(payload, key) #szyfrowanie danych i zwrócenie zaszyfrowanego tekstu


def encrypt_with_user_secret( #szyfruje dane wykorzystując hasło zalogowanego użytkownika jako klucz
    data: Union[str, bytes], # dane do zaszyfrowania
    secret: Union[str, bytes], # hasło zalogowanego użytkownika
) -> str:
    """Szyfruje ``data`` wykorzystując hasło zalogowanego użytkownika jako klucz."""

    payload = data.encode("utf-8") if isinstance(data, str) else data #konwersja danych na bajty jeżeli są w formie stringa
    key = _ensure_user_secret_key(secret) #uzyskanie klucza użytkownika
    return _aes_encrypt(payload, key) #szyfrowanie danych i zwrócenie zaszyfrowanego tekstu
