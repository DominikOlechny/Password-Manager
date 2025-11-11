from __future__ import annotations

from datetime import datetime

import pyodbc

from .db_connection import connect, disconnect
from .tableusers_creation import ensure_users_table
from .tablepassword_creation import ensure_password_store_for_user


def create_user(
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
        Login użytkownika (np. adres e-mail).
    secured_pwd:
        Hasło w postaci zabezpieczonej (np. hash, szyfrogram) jako bytes.
    config_path:
        Ścieżka do pliku konfiguracyjnego z parametrami połączenia.

    Zwraca
    -------
    int
        Identyfikator nowego użytkownika (users_id).
    """
    ensure_users_table(config_path=config_path)

    conn = connect(config_path)
    try:
        cur = conn.cursor()
        cur.execute("USE [password_manager]")

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
            VALUES (?, ?, 0, NULL, 0, 0, SYSUTCDATETIME(), SYSUTCDATETIME())
            """,
            login,
            secured_pwd,
        )
        new_user_id = cur.fetchone()[0]

        # Gwarancja istnienia wspólnej tabeli dbo.entries
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
        conn.rollback()
        raise
    finally:
        disconnect(conn)


def verify_user(
    login: str,
    secured_pwd: bytes,
    config_path: str = "config/db_config.json",
) -> tuple[int, str] | None:
    """
    Weryfikuje użytkownika po loginie i zabezpieczonym haśle.

    Parametry
    ---------
    login:
        Login użytkownika (np. e-mail).
    secured_pwd:
        Hasło w postaci zabezpieczonej (bytes).
    config_path:
        Ścieżka do pliku konfiguracyjnego z parametrami połączenia.

    Zwraca
    -------
    tuple[int, str] | None
        (users_id, login) gdy dane są poprawne i konto nie jest zablokowane,
        None gdy login/hasło są nieprawidłowe lub konto jest zablokowane.
    """
    ensure_users_table(config_path=config_path)
    conn = connect(config_path)
    try:
        cur = conn.cursor()
        cur.execute("USE [password_manager]")
        cur.execute(
            """
            SELECT users_id, login
            FROM dbo.users
            WHERE login = ? AND secured_pwd = ? AND is_locked = 0
            """,
            login,
            secured_pwd,
        )
        row = cur.fetchone()
        cur.close()

        if row is None:
            return None

        return int(row[0]), str(row[1])
    except Exception:
        # nic nie commitujemy, ale dla spójności rollback i ponowne zgłoszenie
        conn.rollback()
        raise
    finally:
        disconnect(conn)
