import json
import pyodbc

USERS_TABLE_SQL = """
IF NOT EXISTS (
    SELECT 1 FROM sys.tables t
    WHERE t.name = 'users' AND t.schema_id = SCHEMA_ID('dbo')
)
BEGIN
    CREATE TABLE dbo.users (
        users_id INT IDENTITY(1,1) PRIMARY KEY,
        login NVARCHAR(255) NOT NULL,
        secured_pwd VARCHAR(MAX) NOT NULL,
        check_mfa BIT NOT NULL CONSTRAINT DF_users_check_mfa DEFAULT 0,
        mfa_secret VARBINARY(MAX) NULL,
        is_locked BIT NOT NULL CONSTRAINT DF_users_is_locked DEFAULT 0,
        failed_attempts INT NOT NULL CONSTRAINT DF_users_failed_attempts DEFAULT 0,
        created_at DATETIME2 NOT NULL CONSTRAINT DF_users_created_at DEFAULT SYSUTCDATETIME(),
        updated_at DATETIME2 NOT NULL CONSTRAINT DF_users_updated_at DEFAULT SYSUTCDATETIME()
    );
END
"""

def _conn_str(cfg, with_db: bool) -> str:
    driver = cfg.get("driver", "ODBC Driver 18 for SQL Server")
    server = cfg["server"]
    port = cfg.get("port", 1433)
    base = (
        f"DRIVER={{{driver}}};SERVER={server},{port};"
        f"UID={cfg['username']};PWD={cfg['password']};"
        "Encrypt=yes;TrustServerCertificate=yes;"
    )
    return base + (f"DATABASE={cfg['database']};" if with_db else "")

def create_database_if_missing(cfg: dict) -> bool:
    """Tworzy bazę jeśli nie istnieje oraz tabelę dbo.users. Zwraca True/False."""
    try:
        # Połączenie do serwera bez wyboru bazy
        with pyodbc.connect(_conn_str(cfg, with_db=False), autocommit=True, timeout=5) as conn:
            cur = conn.cursor()
            cur.execute(
                "IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = ?) "
                f"BEGIN CREATE DATABASE [{cfg['database']}] END",
                (cfg["database"],)
            )
    except pyodbc.Error:
        return False

    try:
        # Połączenie do bazy i utworzenie tabeli users
        with pyodbc.connect(_conn_str(cfg, with_db=True), autocommit=True, timeout=5) as conn_db:
            cur = conn_db.cursor()
            cur.execute(USERS_TABLE_SQL)
        return True
    except pyodbc.Error:
        return False

def connect_to_database(config_path: str = "Settings\\db_config.json"):
    """
    Łączy się z bazą. Jeśli baza nie istnieje, próbuje ją utworzyć.
    Zwraca pyodbc.Connection lub False gdy połączenie się nie powiedzie.
    """
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return False

    # Próba bezpośredniego połączenia do bazy
    try:
        conn = pyodbc.connect(_conn_str(cfg, with_db=True), autocommit=True, timeout=5)
        return conn
    except pyodbc.Error as e:
        # Spróbuj utworzyć bazę tylko, gdy problem to brak bazy
        msg = str(e)
        if "Cannot open database" in msg or "does not exist" in msg:
            if not create_database_if_missing(cfg):
                return False
            try:
                conn = pyodbc.connect(_conn_str(cfg, with_db=True), autocommit=True, timeout=5)
                return conn
            except pyodbc.Error:
                return False
        # Inne błędy (sieć, timeout, DNS, brak instancji) -> False
        return False


# --- Rejestracja użytkownika ---
def insert_user(conn, login, password, created_at):
    try:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO dbo.users (login, secured_pwd, created_at, updated_at)
            VALUES (?, ?, ?, ?)
        """, (login, password, created_at, created_at))
        conn.commit()
        return True
    except Exception as e:
        print("Błąd przy dodawaniu użytkownika:", e)
        return False

def check_user_exists(conn, login):
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM dbo.users WHERE login = ?", (login,))
        return cur.fetchone() is not None
    except Exception as e:
        print("Błąd przy sprawdzaniu użytkownika:", e)
        return False  

# --- Logowanie użytkownika---
def user_login(login: str, pwd_plain: str):
    """Sprawdza poprawność danych logowania w bazie. Zwraca True/False."""
    conn = connect_to_database()
    if conn is False:
        return False

    cur = None
    try:
        cur = conn.cursor()
        # Sprawdź czy konto zablokowane
        cur.execute("SELECT failed_attempts, is_locked FROM dbo.users WHERE login = ?", (login,))
        user = cur.fetchone()
        if user is None:
            return False

        failed_attempts, is_locked = user

        if is_locked:
            print("Konto zablokowane.")
            return False

        # Sprawdź poprawność danych logowania
        cur.execute(
            "SELECT users_id FROM dbo.users WHERE login = ? AND secured_pwd = ?",
            (login, pwd_plain)
        )
        row = cur.fetchone()

        if row:
            # Reset liczby nieudanych prób po poprawnym logowaniu
            cur.execute(
                "UPDATE dbo.users SET failed_attempts = 0 WHERE login = ?",
                (login,)
            )
            conn.commit()
            return True
        else:
            # Zwiększ licznik nieudanych prób
            new_attempts = failed_attempts + 1
            if new_attempts >= 5:
                cur.execute(
                    "UPDATE dbo.users SET failed_attempts = ?, is_locked = 1 WHERE login = ?",
                    (new_attempts, login)
                )
                conn.commit()
                print("Konto zablokowane po 5 nieudanych próbach logowania.")
            else:
                cur.execute(
                    "UPDATE dbo.users SET failed_attempts = ? WHERE login = ?",
                    (new_attempts, login)
                )
                conn.commit()
                print(f"Błędne dane logowania. Próba {new_attempts}/5.")
            return False

    except Exception as e:
        print(f"Błąd logowania: {e}")
        return False
    finally:
        if cur is not None:
            cur.close()
