from db_connection import connect, disconnect

def ensure_database_exists(db_name: str = "password_manager", config_path: str = "config/db_config.json") -> bool:
    cn = connect(config_path)
    try:
        cur = cn.cursor()
        try:
            
            cur.execute("SELECT DB_ID(?)", db_name) # 1 - sprawdzenie
            exists_before = cur.fetchone()[0] is not None
            if exists_before:
                return False

           
            prev_autocommit = cn.autocommit  # 2 - utworzenie w autocommit
            cn.autocommit = True
            try:
                cur.execute("""
IF DB_ID(?) IS NULL
BEGIN
    DECLARE @n sysname = ?;
    EXEC(N'CREATE DATABASE ' + QUOTENAME(@n));
END
""", db_name, db_name)
            finally:
                cn.autocommit = prev_autocommit

            # 3 - weryfikacja
            cur.execute("SELECT DB_ID(?)", db_name)
            exists_after = cur.fetchone()[0] is not None
            return exists_after and not exists_before
        finally:
            cur.close()
    finally:
        disconnect(cn)
        
"""
def testbazy():
    created = ensure_database_exists("password-manager")
    print("Utworzono bazę" if created else "Baza już istniała")

if __name__ == "__main__":
    testbazy()
"""