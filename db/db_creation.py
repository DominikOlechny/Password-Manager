from .db_connection import connect, disconnect #importowanie funkcji connect i disconnect z pliku db_connection.py

def ensure_database_exists(db_name: str = "password_manager", config_path: str = "config/db_config.json") -> bool: #logika tworzenia bazy danych o nazwie password_manager
    cn = connect(config_path) #nawiązanie połączenia z serwerem baz danych
    try:
        cur = cn.cursor() #utworzenie kursora do wykonywania zapytań SQL
        try:
            # 1 - sprawdzenie istnienia bazy danych
            cur.execute("""
                DECLARE @db sysname = ?;
                SELECT DB_ID(@db);
            """, db_name)
            exists_before = cur.fetchone()[0] is not None #sprawdzenie czy baza danych o podanej nazwie już istnieje
            if exists_before: #jeżeli baza danych istnieje to zwróć False
                return False 

            
            prev_autocommit = cn.autocommit #wyłączenie autocommitu na czas tworzenia bazy danych
            cn.autocommit = True #ustawienie autocommitu na True
            try: # 2 - tworzenie bazy danych
                cur.execute("""
IF DB_ID(?) IS NULL
BEGIN
    DECLARE @n sysname = ?;
    DECLARE @sql nvarchar(max) = N'CREATE DATABASE [' + REPLACE(@n, ']', ']]') + N']';
    EXEC(@sql);
END
""", db_name, db_name) #utworzenie bazy danych o podanej nazwie jeżeli nie istnieje
            finally:
                cn.autocommit = prev_autocommit #przywrócenie poprzedniego stanu autocommitu

    
            cur.execute("SELECT DB_ID(?)", db_name) # 3 - potwierdzenie istnienia bazy danych po utworzeniu
            exists_after = cur.fetchone()[0] is not None #sprawdzenie czy baza danych została utworzona
            return exists_after and not exists_before #zwrócenie True jeżeli baza danych została utworzona, False jeżeli istniała wcześniej
        finally:
            cur.close() #zamknięcie kursora
    finally:
        disconnect(cn) #rozłączenie z serwerem baz danych
        
"""
def testbazy():
    created = ensure_database_exists("password-manager")
    print("Utworzono bazę" if created else "Baza już istniała")

if __name__ == "__main__":
    testbazy()
"""