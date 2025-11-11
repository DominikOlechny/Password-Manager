from __future__ import annotations
from datetime import datetime
import pyodbc

from db.db_connection import connect, disconnect
from db.tablepassword_creation import ensure_password_store_for_user


def _get_user_table_name(cur, user_id: int) -> str:
    """Zwraca w pełni kwalifikowaną nazwę tabeli haseł dla użytkownika."""
    cur.execute("SELECT login FROM dbo.users WHERE users_id = ?", user_id)
    row = cur.fetchone()
    if not row or not row[0]:
        raise ValueError(f"user_id {user_id} not found in dbo.users")

    login = str(row[0])

    # Ucieczka znaku ']' w nazwie loginu
    bracketed_login = login.replace("]", "]]")
    return f"dbo.[{bracketed_login} entries]"


def add_password_entry(
    user_id: int,
    service: str,
    account_login: str,
    account_password: bytes,
    expire_date=None,
    *,
    config_path: str = "config/db_config.json",
) -> int:
    """Dodaje nowe hasło użytkownika do dedykowanej tabeli haseł."""
    ensure_password_store_for_user(
        user_id=user_id,
        db_name="password_manager",
        config_path=config_path,
    )

    conn = connect(config_path)
    try:
        cur = conn.cursor()
        cur.execute("USE [password_manager]")
        table_name = _get_user_table_name(cur, user_id)

        cur.execute(
            f"""
            INSERT INTO {table_name} (
                user_id,
                service,
                login,
                password,
                created_at,
                updated_at,
                expire_date
            )
            OUTPUT INSERTED.id
            VALUES (?, ?, ?, ?, SYSUTCDATETIME(), SYSUTCDATETIME(), ?)
            """,
            user_id,
            service,
            account_login,
            account_password,
            expire_date,
        )
        new_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        return int(new_id)
    except Exception:
        conn.rollback()
        raise
    finally:
        disconnect(conn)


def list_password_entries(
    user_id: int,
    *,
    config_path: str = "config/db_config.json",
):
    """Zwraca listę wpisów użytkownika (id, service, login, created_at, expire_date)."""
    ensure_password_store_for_user(
        user_id=user_id,
        db_name="password_manager",
        config_path=config_path,
    )

    conn = connect(config_path)
    try:
        cur = conn.cursor()
        cur.execute("USE [password_manager]")
        table_name = _get_user_table_name(cur, user_id)

        cur.execute(
            f"""
            SELECT
                id,
                service,
                login,
                created_at,
                expire_date
            FROM {table_name}
            WHERE user_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            user_id,
        )
        rows = cur.fetchall()
        cur.close()

        result: list[tuple[int, str, str, datetime, datetime | None]] = []
        for r in rows:
            result.append(
                (
                    int(r.id),
                    str(r.service),
                    str(r.login),
                    r.created_at,
                    r.expire_date,
                )
            )
        return result
    finally:
        disconnect(conn)


def update_password_entry(
    user_id: int,
    entry_id: int,
    *,
    new_service=None,
    new_login=None,
    new_password=None,
    new_expire_date=None,
    config_path: str = "config/db_config.json",
) -> bool:
    """Aktualizuje wskazany wpis użytkownika."""
    ensure_password_store_for_user(
        user_id=user_id,
        db_name="password_manager",
        config_path=config_path,
    )

    conn = connect(config_path)
    try:
        cur = conn.cursor()
        cur.execute("USE [password_manager]")
        table_name = _get_user_table_name(cur, user_id)

        cur.execute(
            f"""
            UPDATE {table_name}
            SET
                service = COALESCE(?, service),
                login = COALESCE(?, login),
                password = COALESCE(?, password),
                expire_date = COALESCE(?, expire_date),
                updated_at = SYSUTCDATETIME()
            WHERE id = ? AND user_id = ?
            """,
            new_service,
            new_login,
            new_password,
            new_expire_date,
            entry_id,
            user_id,
        )
        affected = cur.rowcount
        conn.commit()
        cur.close()
        return affected == 1
    except Exception:
        conn.rollback()
        raise
    finally:
        disconnect(conn)


def delete_password_entry(
    user_id: int,
    entry_id: int,
    *,
    config_path: str = "config/db_config.json",
) -> bool:
    """Usuwa wpis użytkownika o podanym ID."""
    ensure_password_store_for_user(
        user_id=user_id,
        db_name="password_manager",
        config_path=config_path,
    )

    conn = connect(config_path)
    try:
        cur = conn.cursor()
        cur.execute("USE [password_manager]")
        table_name = _get_user_table_name(cur, user_id)

        cur.execute(
            f"DELETE FROM {table_name} WHERE id = ? AND user_id = ?",
            entry_id,
            user_id,
        )
        affected = cur.rowcount
        conn.commit()
        cur.close()
        return affected == 1
    except Exception:
        conn.rollback()
        raise
    finally:
        disconnect(conn)
