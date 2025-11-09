from .db_connection import connect, disconnect
from .db_creation import ensure_database_exists

def ensure_users_table(
    db_name: str = "password_manager",
    config_path: str = "config/db_config.json",
) -> bool:
    # 1. Upewnij się, że baza istnieje
    ensure_database_exists(db_name=db_name, config_path=config_path)

    conn = connect(config_path)
    try:
        cur = conn.cursor()

        # 2. Wejdź w kontekst bazy bez parametrów
        escaped = db_name.replace("]", "]]")
        cur.execute(f"USE [{escaped}]")

        # 3. Sprawdź czy tabela istnieje
        cur.execute("SELECT OBJECT_ID(N'dbo.users', N'U')")
        exists_before = cur.fetchone()[0] is not None
        if exists_before:
            return False

        # 4. Utwórz tabelę i unikalny indeks na login
        cur.execute("""
CREATE TABLE dbo.users (
    users_id        INT IDENTITY(1,1) PRIMARY KEY,
    login           NVARCHAR(255)   NOT NULL,
    secured_pwd     VARBINARY(MAX)  NOT NULL,
    check_mfa       BIT             NOT NULL CONSTRAINT DF_users_check_mfa DEFAULT(0),
    mfa_secret      VARBINARY(MAX)  NULL,
    is_locked       BIT             NOT NULL CONSTRAINT DF_users_is_locked DEFAULT(0),
    failed_attempts INT             NOT NULL CONSTRAINT DF_users_failed_attempts DEFAULT(0),
    created_at      DATETIME2(0)    NOT NULL CONSTRAINT DF_users_created_at DEFAULT (SYSUTCDATETIME()),
    updated_at      DATETIME2(0)    NOT NULL CONSTRAINT DF_users_updated_at DEFAULT (SYSUTCDATETIME())
);
""")

        # zabezpieczenie przed powtórnym uruchomieniem
        cur.execute("""
IF NOT EXISTS (
    SELECT 1 FROM sys.indexes
    WHERE name = N'UX_users_login' AND object_id = OBJECT_ID(N'dbo.users')
)
    CREATE UNIQUE INDEX UX_users_login ON dbo.users(login);
""")

        conn.commit()
        return True
    finally:
        disconnect(conn)

"""
def testtabeli():
    created = ensure_users_table()
    print("Tabela użytkowników została utworzona." if created else "Tabela użytkowników już istnieje.")

testtabeli():
"""