# connection_database.py
import json
import pyodbc
import base64

# nowo: import kryptografii z modułu użytkownika
from crypto_module import encrypt as aes_encrypt, decrypt as aes_decrypt, aes_key  # noqa

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
    try:
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
        with pyodbc.connect(_conn_str(cfg, with_db=True), autocommit=True, timeout=5) as conn_db:
            cur = conn_db.cursor()
            cur.execute(USERS_TABLE_SQL)
        return True
    except pyodbc.Error:
        return False

def connect_to_database(config_path: str = "Settings\\db_config.json"):
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception:
        return False

    try:
        conn = pyodbc.connect(_conn_str(cfg, with_db=True), autocommit=True, timeout=5)
        return conn
    except pyodbc.Error as e:
        msg = str(e)
        if "Cannot open database" in msg or "does not exist" in msg:
            if not create_database_if_missing(cfg):
                return False
            try:
                conn = pyodbc.connect(_conn_str(cfg, with_db=True), autocommit=True, timeout=5)
                return conn
            except pyodbc.Error:
                return False
        return False

# --- narzędzia do szyfrowania haseł ---

def _pack_nonce_ct(nonce: bytes, ct: bytes) -> str:
    """Pakuj nonce i ciphertext do JSON jako base64."""
    return json.dumps({
        "n": base64.b64encode(nonce).decode("ascii"),
        "c": base64.b64encode(ct).decode("ascii"),
    }, separators=(",", ":"))

def _unpack_nonce_ct(packed: str) -> tuple[bytes, bytes]:
    obj = json.loads(packed)
    return base64.b64decode(obj["n"]), base64.b64decode(obj["c"])

def _encrypt_pwd_str(pwd_plain: str) -> str:
    """Zwraca JSON z nonce i ciphertext w base64."""
    ct, nonce = aes_encrypt(pwd_plain.encode("utf-8"), aes_key)
    return _pack_nonce_ct(nonce, ct)

def _try_decrypt_pwd_to_str(stored: str) -> tuple[bool, str]:
    """
    Próbuje odszyfrować zapisany JSON. Jeśli to nie JSON, traktuje jako plaintext.
    Zwraca (ok, plaintext).
    """
    try:
        nonce, ct = _unpack_nonce_ct(stored)
        plain = aes_decrypt(ct, nonce, aes_key).decode("utf-8")
        return True, plain
    except Exception:
        # wsteczna zgodność: stare rekordy trzymane jako plaintext
        return False, stored

# --- Rejestracja użytkownika ---
def insert_user(conn, login, password, created_at):
    try:
        cur = conn.cursor()
        secured = _encrypt_pwd_str(password)  # szyfrowanie przed zapisem
        cur.execute("""
            INSERT INTO dbo.users (login, secured_pwd, created_at, updated_at)
            VALUES (?, ?, ?, ?)
        """, (login, secured, created_at, created_at))
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

# --- Logowanie użytkownika ---
def user_login(login: str, pwd_plain: str):
    """
    Weryfikuje logowanie:
    - Jeśli konto zablokowane -> False
    - Deszyfruje secured_pwd i porównuje z pwd_plain
    - Liczy próby i blokuje po >=5
    """
    conn = connect_to_database()
    if conn is False:
        return False

    cur = None
    try:
        cur = conn.cursor()
        cur.execute("SELECT failed_attempts, is_locked, secured_pwd FROM dbo.users WHERE login = ?", (login,))
        row = cur.fetchone()
        if row is None:
            return False

        failed_attempts, is_locked, stored_sec = row

        if is_locked:
            print("Konto zablokowane.")
            return False

        # odszyfrowanie lub porównanie do wstecznie zgodnego plaintextu
        _, stored_plain = _try_decrypt_pwd_to_str(stored_sec)

        if stored_plain == pwd_plain:
            cur.execute("UPDATE dbo.users SET failed_attempts = 0 WHERE login = ?", (login,))
            conn.commit()
            return True
        else:
            new_attempts = (failed_attempts or 0) + 1
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
