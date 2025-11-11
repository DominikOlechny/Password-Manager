from __future__ import annotations
from datetime import datetime
import pyodbc

from .db_connection import connect, disconnect
from .tablepassword_creation import ensure_password_store_for_user


def add_password_entry(
    user_id: int,
    user_login: str,
    service: str,
    account_login: str,
    account_password: bytes,
    expire_date=None,
    *,
    config_path: str = "config/db_config.json",
) -> int:
    """Dodaje nowe hasło użytkownika do wspólnej tabeli dbo.entries."""
    ensure_password_store_for_user(
        user_id=user_id,
        db_name="password_manager",
        config_path=config_path,
    )

    conn = connect(config_path)
    try:
        cur = conn.cursor()
        cur.execute("USE [password_manager]")
        cur.execute(
            """
            INSERT INTO dbo.entries (
                user_id,
                user_login,
                service,
                login,
                password,
                created_at,
                updated_at,
                expire_date
            )
            OUTPUT INSERTED.id
            VALUES (?, ?, ?, ?, ?, SYSUTCDATETIME(), SYSUTCDATETIME(), ?)
            """,
            user_id,
            user_login,
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
        cur.execute(
            """
            SELECT id, service, login, created_at, expire_date
            FROM dbo.entries
            WHERE user_id = ?
            ORDER BY created_at DESC, id DESC
            """,
            user_id,
        )
        rows = cur.fetchall()
        cur.close()
        result = []
        for r in rows:
            result.append((int(r.id), str(r.service), str(r.login), r.created_at, r.expire_date))
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
        cur.execute(
            """
            UPDATE dbo.entries
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
        cur.execute(
            "DELETE FROM dbo.entries WHERE id = ? AND user_id = ?",
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
