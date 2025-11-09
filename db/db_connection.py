import json
import pyodbc

#Logika połaczenia z baza danych, uzywane dane do polaczenia sa z pliku json config\db_config.json
def connect(path: str = "config/db_config.json"):
    with open(path, "r", encoding="utf-8") as f:
        c = json.load(f)

    server = f"{c['server']},{c['port']}" if c.get("port") else c["server"]
    driver = c.get("driver", "ODBC Driver 18 for SQL Server")
    trust = "yes" if c.get("trust_server_certificate", True) else "no"

    parts = [
        f"DRIVER={{{driver}}}",
        f"SERVER={server}",
        "Encrypt=yes",
        f"TrustServerCertificate={trust}",
        # Brak wpisu DATABASE - laczenie tylko do instancji
    ]

    if c.get("username") and c.get("password"):
        parts += [f"UID={c['username']}", f"PWD={c['password']}"]
    else:
        parts += ["Trusted_Connection=yes"]

    conn_str = ";".join(parts)
    timeout = int(c.get("timeout", 5))
    return pyodbc.connect(conn_str, timeout=timeout, autocommit=False)


# Logika rozłączania z bazą danych
def disconnect(conn) -> None:
    if conn:
        try:
            conn.close()
        except:
            pass


def testbazy():
    conn = None
    try:
        conn = connect()
        print("STATUS: OK")  # połączenie nawiązane
    except Exception as e:
        print("STATUS: FAIL")
        print(f"DETAILS: {e}")
    finally:
        disconnect(conn)

testbazy()