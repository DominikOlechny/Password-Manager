from datetime import datetime #importowanie klasy datetime z modułu datetime

import pyodbc #importowanie modułu pyodbc do obsługi połączeń z bazą danych

from .db_connection import connect, disconnect #importowanie funkcji connect i disconnect z pliku db_connection.py
from .tableusers_creation import ensure_users_table #importowanie funkcji ensure_users_table z pliku tableusers_creation.py
from .tablepassword_creation import ensure_password_store_for_user #importowanie funkcji ensure_password_store_for_user z pliku tablepassword_creation.py
from security.decrypt import decrypt_with_json_key # importowanie funkcji decrypt_with_json_key z pliku security/decrypt.py


def create_user( #tworzy nowego użytkownika w dbo.users i zwraca jego users_id
    login: str,
    secured_pwd: bytes,
    *,
    config_path: str = "config/db_config.json",
) -> int:
    """
    Tworzy nowego użytkownika w dbo.users i zwraca jego users_id.

    Parametry
    ---------
    login:
        Login użytkownika.
    secured_pwd:
        Hasło w postaci zabezpieczonej jako bytes, gotowe do zapisania w VARBINARY.
    config_path:
        Ścieżka do pliku konfiguracyjnego z parametrami połączenia.

    Zwraca
    -------
    int
        Identyfikator nowego użytkownika (users_id).
    """
    ensure_users_table(config_path=config_path) #upewnij się, że tabela użytkowników istnieje
    conn = connect(config_path) #nawiązanie połączenia z bazą danych
    try: 
        cur = conn.cursor()
        cur.execute("USE [password_manager]")

        # wstawienie użytkownika z domyślnymi flagami bezpieczeństwa
        cur.execute(
            """
            INSERT INTO dbo.users (
                login,
                secured_pwd,
                check_mfa,
                mfa_secret,
                is_locked,
                failed_attempts,
                created_at,
                updated_at
            )
            OUTPUT INSERTED.users_id
            VALUES (
                ?,
                ?,
                0,
                NULL,
                0,
                0,
                SYSUTCDATETIME(),
                SYSUTCDATETIME()
            )
            """,
            login,
            secured_pwd,
        )
        new_user_id = cur.fetchone()[0]

        # gwarancja istnienia wspólnej tabeli dbo.entries
        ensure_password_store_for_user(
            user_id=new_user_id,
            conn=conn,
            db_name="password_manager",
            config_path=config_path,
        )

        conn.commit()
        cur.close()
        return int(new_user_id)
    except Exception:
        # nic nie commitujemy, ale dla spójności rollback i ponowne zgłoszenie
        conn.rollback()
        raise
    finally:
        disconnect(conn)


def verify_user( #weryfikuje użytkownika po loginie i haśle w postaci jawnej
    login: str,
    password: str,
    config_path: str = "config/db_config.json",
) -> tuple[int, str] | None:
    """
    Weryfikuje użytkownika po loginie i haśle w postaci jawnej.

    Parametry
    ---------
    login:
        Login użytkownika.
    password:
        Hasło w postaci czystego tekstu, które zostanie porównane po odszyfrowaniu
        wartości zapisanej w bazie.
    config_path:
        Ścieżka do pliku konfiguracyjnego z parametrami połączenia.

    Zwraca
    -------
    tuple[int, str] | None
        (users_id, login) gdy dane są poprawne i konto nie jest zablokowane,
        None w pozostałych przypadkach.
    """
    ensure_users_table(config_path=config_path)
    conn = connect(config_path)
    try:
        cur = conn.cursor()
        cur.execute("USE [password_manager]")
        cur.execute(
            """
            SELECT users_id, login, secured_pwd
            FROM dbo.users
            WHERE login = ? AND is_locked = 0
            """,
            login,
        )
        row = cur.fetchone()
        if row is None:
            cur.close()
            return None

        user_id = int(row[0])
        user_login = str(row[1])
        stored_encrypted = row[2]

        if stored_encrypted is None:
            cur.close()
            return None

        # secured_pwd jest przechowywane w VARBINARY jako zaszyfrowany tekst ASCII
        encrypted_password = bytes(stored_encrypted).decode("ascii")

        cur.close()

        decrypted_password = decrypt_with_json_key(encrypted_password).decode("utf-8") # odszyfrowanie hasła
        if decrypted_password != password:
            return None

        return user_id, user_login # zwrócenie identyfikatora użytkownika i loginu
    finally:
        disconnect(conn) #rozłączenie z bazą danych
