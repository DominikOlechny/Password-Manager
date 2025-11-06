import getpass
from datetime import datetime
from connection_database import insert_user, check_user_exists, connect_to_database, user_login
from settings_edit import settings_modify
import sys

def menu_registration():
    """Rejestruje nowego uzytkownika w dbo.users. Zwraca True/False."""
    conn = connect_to_database()
    if conn is False:
        print("Brak polaczenia z baza.")
        return False

    try:
        login = input("Podaj login: ").strip()
        if not login:
            print("Login nie moze byc pusty.")
            return False

        pwd_plain = getpass.getpass("Podaj haslo: ")
        if not pwd_plain:
            print("Haslo nie moze byc puste.")
            return False

        exists = check_user_exists(conn, login)
        if exists is None:
            print("Blad przy sprawdzaniu uzytkownika. Sprobuj ponownie.")
            return False
        if exists:
            print("Uzytkownik o takim loginie juz istnieje.")
            return False

        now = datetime.utcnow()
        if insert_user(conn, login, pwd_plain, now):
            print(f"Uzytkownik '{login}' zostal zarejestrowany.")
            return True
        else:
            print("Blad podczas rejestracji.")
            return False
    finally:
        conn.close()
        
def menu_login():
    """Pobiera dane logowania od użytkownika, waliduje i przekazuje do bazy."""
    login = input("Podaj login: ").strip()
    if not login:
        print("Login nie może być pusty.")
        return False

    pwd_plain = getpass.getpass("Podaj hasło: ")
    if not pwd_plain:
        print("Hasło nie może być puste.")
        return False

    result = user_login(login, pwd_plain)
    if result:
        print(f"Zalogowano pomyślnie jako '{login}'.")
        return True
    else:
        print("Nieprawidłowy login lub hasło.")
        return False



def main_menu():
    while True:
        print("\n--- MENU ---")
        print("1. Zaloguj")
        print("2. Zarejestruj")
        print("3. Opcje polaczenia")
        print("4. wyjdz")

        choice = input("Wybierz opcje (1-3): ").strip()

        if choice == "1":
            if menu_login():
                print("Zalogowano pomyslnie.")
                break
        elif choice == "2":
            menu_registration()
        elif choice == "3":
            print("Wprowadz dane polaczenia z serwerem")
            settings_modify()
        elif choice == "4":
            print("Zamykanie programu...")
            sys.exit()
        else:
            print("Niepoprawny wybor, sproboj ponownie.")

if __name__ == "__main__":
    main_menu()