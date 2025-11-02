import os
import json
import getpass
from typing import Tuple, Any
from connection_database import connect_to_database

CONFIG_DIR = os.path.join("Settings")
CONFIG_PATH = os.path.join(CONFIG_DIR, "db_config.json")
LEGACY_PATH = "db_config.json"

def _load_db_cfg() -> Tuple[dict, str]:
    """Wczytaj config. Jesli brak - zwroc domyslne i sciezke docelowa."""
    path = CONFIG_PATH if os.path.exists(CONFIG_PATH) else (
        LEGACY_PATH if os.path.exists(LEGACY_PATH) else CONFIG_PATH
    )
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f), path
    # domyslne
    return {
        "driver": "ODBC Driver 18 for SQL Server",
        "server": "localhost",
        "port": 1433,
        "database": "PasswordManagerDB",
        "username": "sa",
        "password": ""
    }, CONFIG_PATH

def _prompt(cur: Any, label: str, secret: bool = False, caster=None):
    shown = "********" if secret and cur else str(cur)
    prompt = f"{label} [{shown}]: "
    val = getpass.getpass(prompt) if secret else input(prompt).strip()
    if val == "":
        return cur
    if caster:
        try:
            return caster(val)
        except Exception:
            print(f"Nieprawidlowa wartosc - sprobuj ponownie.")
            return _prompt(cur, label, secret, caster)
    return val

def settings_modify() -> bool:
    """
    Edycja Settings/db_config.json + test polaczenia.
    Keys: driver, server, port, database, username, password.
    """
    cfg, src_path = _load_db_cfg()

    print("\nEdytor ustawien polaczenia z MSSQL")
    print("Enter - zachowuje biezaca wartosc.\n")

    cfg["driver"]   = _prompt(cfg.get("driver", "ODBC Driver 18 for SQL Server"), "Driver")
    cfg["server"]   = _prompt(cfg.get("server", "localhost"), "Server")
    cfg["port"]     = _prompt(cfg.get("port", 1433), "Port", caster=int)
    cfg["database"] = _prompt(cfg.get("database", "PasswordManagerDB"), "Database")
    cfg["username"] = _prompt(cfg.get("username", "sa"), "Username")
    cfg["password"] = _prompt(cfg.get("password", ""), "Password", secret=True)

    # walidacja
    errors = []
    if not cfg["server"]: errors.append("server")
    if not cfg["database"]: errors.append("database")
    if not cfg["username"]: errors.append("username")
    if not isinstance(cfg["port"], int) or not (1 <= cfg["port"] <= 65535): errors.append("port")
    if errors:
        print("Bledne pola: " + ", ".join(errors))
        return False

    # zapis
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    print(f"Zapisano konfiguracje: {CONFIG_PATH}")

    # test polaczenia
    conn = connect_to_database(CONFIG_PATH)
    if conn:
        try:
            print("Test polaczenia: OK")
            return True
        finally:
            conn.close()
    print("Test polaczenia: BLAD - sprawdz ustawienia lub siec.")
    return False