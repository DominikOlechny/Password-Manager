import json #importowanie modułu json celem odczytania pliku JSON
import pyodbc #importowanie modułu pyodbc do obsługi połączeń z bazą danych


def connect(path: str = "config/db_config.json"): #Logika połaczenia z baza danych, uzywane dane do polaczenia sa z pliku json config\db_config.json
    with open(path, "r", encoding="utf-8") as f:
        c = json.load(f)

    server = f"{c['server']},{c['port']}" if c.get("port") else c["server"] #Utworzenie ciagu polaczenia z serwerem
    driver = c.get("driver", "ODBC Driver 18 for SQL Server") 
    trust = "yes" if c.get("trust_server_certificate", True) else "no" 

    parts = [
        f"DRIVER={{{driver}}}",  #Utworzenie ciagu polaczenia z uzyciem sterownika ODBC
        f"SERVER={server}",  #Utworzenie ciagu polaczenia z serwerem
        "Encrypt=yes", #Zawsze uzywaj szyfrowania
        f"TrustServerCertificate={trust}", #Ustawienie zaufania do certyfikatu serwera
    ]

    if c.get("username") and c.get("password"):  #jeżeli podano nazwe uzytkownika i haslo to dodaj je do ciagu polaczenia
        parts += [f"UID={c['username']}", f"PWD={c['password']}"]
    else:
        parts += ["Trusted_Connection=yes"] #jeżeli nie podano to uzyj polaczenia zaufanego (Windows Authentication)

    conn_str = ";".join(parts) #Utworzenie koncowego ciagu polaczenia
    timeout = int(c.get("timeout", 5)) #pobranie timeoutu z pliku konfiguracyjnego lub ustawienie domyślnej wartosci 5 sekund
    return pyodbc.connect(conn_str, timeout=timeout, autocommit=False) #zwrócenie obiektu połączenia z bazą danych



def disconnect(conn) -> None: # Logika rozłączania z bazą danych
    if conn:
        try:
            conn.close()
        except:
            pass

""" pozostawiona logika do testowania bazy danych. 
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
"""