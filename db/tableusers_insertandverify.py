from .db_connection import connect, disconnect
from .tablepassword_creation import ensure_password_store_for_user
from .tableusers_creation import ensure_users_table


def create_user(
    login: str,
    secured_pwd: bytes,
    check_mfa: bool = False,
    mfa_secret: bytes | None = None,
    is_locked: bool = False,
    failed_attempts: int = 0,
    config_path: str = "config/db_config.json",
) -> None:
    """Dodaje nowego użytkownika do tabeli `dbo.users` i gwarantuje istnienie `dbo.entries`."""
    ensure_users_table(config_path=config_path)  # użyje domyślnej bazy jeśli nie podasz
    conn = connect(config_path)
    try:
        cur = conn.cursor()
        # praca na kontekście bazy password_manager (spójnie z wcześniejszymi plikami)
        cur.execute("USE [password_manager]")

        # OUTPUT musi być pobrany PRZED commit
        cur.execute(
            """
            INSERT INTO dbo.users (
                login, secured_pwd, check_mfa, mfa_secret, is_locked, failed_attempts,
                created_at, updated_at
            )
            OUTPUT INSERTED.users_id
            VALUES (?, ?, ?, ?, ?, ?, SYSUTCDATETIME(), SYSUTCDATETIME())
            """,
            login,
            secured_pwd,
            int(check_mfa),
            mfa_secret,
            int(is_locked),
            failed_attempts,
        )
        new_user_id = cur.fetchone()[0]

        # zamiast tworzyć tabelę per user - gwarantujemy wspólną tabelę entries
        ensure_password_store_for_user(
            user_id=new_user_id,
            conn=conn,
            db_name="password_manager",
            config_path=config_path,
        )

        conn.commit()
        cur.close()
    except Exception:
        conn.rollback()
        raise
    finally:
        disconnect(conn)


def verify_user(
    login: str,
    secured_pwd: bytes,
    config_path: str = "config/db_config.json",
) -> bool:
    """Sprawdza, czy istnieje użytkownik o podanym loginie i zaszyfrowanym haśle."""
    ensure_users_table(config_path=config_path)
    conn = connect(config_path)
    try:
        cur = conn.cursor()
        cur.execute("USE [password_manager]")
        cur.execute(
            "SELECT COUNT(*) FROM dbo.users WHERE login = ? AND secured_pwd = ? AND is_locked = 0",
            login,
            secured_pwd,
        )
        exists = cur.fetchone()[0] > 0
        cur.close()
        return exists
    except Exception:
        conn.rollback()
        raise
    finally:
        disconnect(conn)
