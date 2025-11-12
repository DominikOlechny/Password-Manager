from .db_connection import connect, disconnect #importowanie funkcji connect i disconnect z pliku db_connection.py
from .tableusers_creation import ensure_users_table #importowanie funkcji ensure_users_table z pliku tableusers_creation.py


def ensure_password_store_for_user( #upewnij się, że tabela przechowywania haseł dla użytkownika istnieje
    user_id: int,
    *,
    db_name: str = "password_manager",
    config_path: str = "config/db_config.json",
    conn=None,
) -> bool:
    """Ensure per-user table dbo.[{login} entries] exists.

    Zwraca True gdy utworzono, False gdy istniała.
    """
    if user_id <= 0:
        raise ValueError("user_id must be a positive integer")

    ensure_users_table(db_name=db_name, config_path=config_path)

    own_connection = conn is None #sprawdzenie czy przekazano połączenie
    if own_connection: #jeżeli nie to nawiąż połączenie
        conn = connect(config_path)
    cur = conn.cursor() #utworzenie kursora do wykonywania zapytań SQL
    try:
        escaped_db = db_name.replace("]", "]]") #ucieczka nazwy bazy danych
        cur.execute(f"USE [{escaped_db}]") #przełączenie na odpowiednią bazę danych

        # Pobierz login dla users_id
        cur.execute("SELECT login FROM dbo.users WHERE users_id = ?", user_id)
        row = cur.fetchone()
        if not row or not row[0]:
            raise ValueError(f"user_id {user_id} not found in dbo.users")
        login = str(row[0])

        # Zbuduj bezpieczną nazwę tabeli: dbo.[{login} entries]
        # Uwaga: ']' w nazwie należy podwoić wewnątrz nawiasów kwadratowych.
        bracketed_login = login.replace("]", "]]")
        table_bracketed = f"[{bracketed_login} entries]"
        full_table_name = f"dbo.{table_bracketed}"

        # Sprawdź istnienie tabeli po nazwie i schemacie, bez ucieczki w OBJECT_ID
        cur.execute(
            """
            SELECT 1
            FROM sys.tables t
            JOIN sys.schemas s ON s.schema_id = t.schema_id
            WHERE t.name = ? AND s.name = 'dbo'
            """,
            f"{login} entries",
        )
        exists_before = cur.fetchone() is not None #sprawdzenie czy tabela już istnieje

        if exists_before: #jeżeli tabela istnieje to zwróć False
            created = False
        else: 
            # Utwórz tabelę 1:1 z dokumentacją i FK do users
            ddl = f"""
CREATE TABLE {full_table_name} (
    id BIGINT IDENTITY(1,1) PRIMARY KEY,
    user_id INT NOT NULL,
    service NVARCHAR(255) NOT NULL,
    login NVARCHAR(255) NOT NULL,
    password VARBINARY(MAX) NOT NULL,
    created_at DATETIME2(0) NOT NULL DEFAULT (SYSUTCDATETIME()),
    updated_at DATETIME2(0) NOT NULL DEFAULT (SYSUTCDATETIME()),
    expire_date DATETIME2(0) NULL,
    CONSTRAINT FK_{login.replace(' ', '_')}_entries_users
        FOREIGN KEY (user_id) REFERENCES dbo.users(users_id)
);
CREATE INDEX IX_{login.replace(' ', '_')}_entries_user_id ON {full_table_name}(user_id);
CREATE INDEX IX_{login.replace(' ', '_')}_entries_service ON {full_table_name}(service);
"""
            cur.execute(ddl)
            created = True

    except Exception: #w przypadku wyjątku zamknij kursor i rozłącz jeżeli to własne połączenie
        cur.close()
        if own_connection:
            conn.rollback()
            disconnect(conn)
        raise
    else: #w przypadku sukcesu zamknij kursor i rozłącz jeżeli to własne połączenie
        cur.close()
        if own_connection:
            conn.commit()
            disconnect(conn)
        return created #zwrócenie czy tabela została utworzona


__all__ = ["ensure_password_store_for_user"] #eksportowanie funkcji ensure_password_store_for_user
