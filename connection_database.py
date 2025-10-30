import json
import pyodbc
import getpass
from datetime import datetime

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

def create_database_if_missing(cfg: dict):
    """Tworzy bazę jeśli nie istnieje, a potem tabelę dbo.users."""
    # Połączenie do serwera bez wyboru bazy
    with pyodbc.connect(_conn_str(cfg, with_db=False), autocommit=True, timeout=5) as conn:
        cur = conn.cursor()
        cur.execute(
            f"IF NOT EXISTS (SELECT 1 FROM sys.databases WHERE name = ?) "
            f"BEGIN CREATE DATABASE [{cfg['database']}] END",
            (cfg["database"],)
        )

    # Połączenie do nowej/istniejącej bazy i utworzenie tabeli users
    with pyodbc.connect(_conn_str(cfg, with_db=True), autocommit=True, timeout=5) as conn_db:
        cur = conn_db.cursor()
        cur.execute(USERS_TABLE_SQL)

def connect_to_database(config_path: str = "Settings\\db_config.json"):
    """Łączy się z bazą. Jeśli baza nie istnieje, tworzy ją i tabelę dbo.users, potem łączy ponownie."""
    with open(config_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    try:
        conn = pyodbc.connect(_conn_str(cfg, with_db=True), autocommit=True, timeout=5)
        return conn
    except pyodbc.Error as e:
        # Gdy baza nie istnieje lub brak dostępu – spróbuj utworzyć
        if "Cannot open database" in str(e) or "Login failed for user" not in str(e):
            create_database_if_missing(cfg)
            return pyodbc.connect(_conn_str(cfg, with_db=True), autocommit=True, timeout=5)
        raise



import getpass
import pyodbc
from datetime import datetime

def user_registration():
    """
    Rejestruje nowego użytkownika w tabeli dbo.users.
    Hasło przechowywane w formie jawnej (NVARCHAR).
    """
    conn = connect_to_database()  # używa wcześniej zdefiniowanej funkcji
    try:
        cur = conn.cursor()

        login = input("Podaj login: ").strip()
        if not login:
            print("Login nie może być pusty.")
            return

        pwd_plain = getpass.getpass("Podaj hasło: ")
        if not pwd_plain:
            print("Hasło nie może być puste.")
            return

        # sprawdzenie duplikatu
        cur.execute("SELECT 1 FROM dbo.users WHERE login = ?", (login,))
        if cur.fetchone():
            print("Użytkownik o takim loginie już istnieje.")
            return

        now = datetime.utcnow()

        # zapis hasła w formie tekstowej
        cur.execute("""
            INSERT INTO dbo.users (login, secured_pwd, created_at, updated_at)
            VALUES (?, ?, ?, ?)
        """, (login, pwd_plain, now, now))

        conn.commit()
        print(f"Użytkownik '{login}' został zarejestrowany.")

    except Exception as e:
        print("Błąd podczas rejestracji:", e)
    finally:
        cur.close()
        conn.close()

def user_login():
    """
    Logowanie użytkownika.
    Sprawdza, czy istnieje rekord w dbo.users z podanym loginem i hasłem (plaintext).
    """
    conn = connect_to_database()
    try:
        cur = conn.cursor()

        login = input("Login: ").strip()
        if not login:
            print("Login nie może być pusty.")
            return

        pwd_plain = getpass.getpass("Hasło: ")
        if not pwd_plain:
            print("Hasło nie może być puste.")
            return

        cur.execute(
            "SELECT users_id FROM dbo.users WHERE login = ? AND secured_pwd = ?",
            (login, pwd_plain)
        )
        row = cur.fetchone()

        if row:
            print(f"Zalogowano pomyślnie jako '{login}'. (ID: {row[0]})")
            return True
        else:
            print("Nieprawidłowy login lub hasło.")
            return False

    except Exception as e:
        print("Błąd podczas logowania:", e)
        return False
    finally:
        cur.close()
        conn.close()

