from db_connection import connect, disconnect
from tableusers_creation import ensure_users_table


def create_user(
    login: str,
    secured_pwd: bytes,
    check_mfa: bool = False,
    mfa_secret: bytes | None = None,
    is_locked: bool = False,
    failed_attempts: int = 0,
    config_path: str = "config/db_config.json",
) -> None:
    """Dodaje nowego użytkownika do tabeli ``dbo.users``."""
    ensure_users_table(config_path=config_path)

    conn = connect(config_path)
    try:
        cur = conn.cursor()

        # upewniamy się, że pracujemy na bazie password_manager
        cur.execute("USE [password_manager]")

        cur.execute(
            """
            INSERT INTO dbo.users (
                login,
                secured_pwd,
                check_mfa,
                mfa_secret,
                is_locked,
                failed_attempts
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            login,
            secured_pwd,
            int(check_mfa),
            mfa_secret,
            int(is_locked),
            failed_attempts,
        )
        conn.commit()
        cur.close()
    finally:
        disconnect(conn)


def verify_user(
    login: str,
    secured_pwd: bytes,
    config_path: str = "config/db_config.json",
) -> bool:
    """Sprawdza, czy istnieje użytkownik o podanym loginie i haśle."""
    ensure_users_table(config_path=config_path)

    conn = connect(config_path)
    try:
        cur = conn.cursor()

        # ten sam kontekst bazy co wyżej
        cur.execute("USE [password_manager]")

        cur.execute(
            "SELECT COUNT(*) FROM dbo.users WHERE login = ? AND secured_pwd = ?",
            login,
            secured_pwd,
        )
        exists = cur.fetchone()[0] > 0
        cur.close()
        return exists
    finally:
        disconnect(conn)

"""
def test_create_and_verify_user(config_path: str = "config/db_config.json") -> None:
    """ """Funkcja testowa: tworzy użytkownika i sprawdza, czy istnieje. """ """
    login = "test_user_" + secrets.token_hex(4)
    password = b"test_pass"

    print(f"Tworze uzytkownika: {login}")

    create_user(login, password, config_path=config_path)

    if verify_user(login, password, config_path=config_path):
        print("Test OK - uzytkownik istnieje w bazie.")
    else:
        print("Test NIEUDANY - uzytkownik nie zostal znaleziony.")


if __name__ == "__main__":
    test_create_and_verify_user()
"""