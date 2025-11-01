import getpass
from datetime import datetime
from connection_database import insert_user, check_user_exists, connect_to_database, user_login

def menu_registration():
    """Rejestruje nowego użytkownika w dbo.users. Zwraca True/False."""
    conn = connect_to_database()
    if conn is False:
        print("Brak połączenia z bazą.")
        return False

    login = input("Podaj login: ").strip()
    if not login:
        print("Login nie może być pusty.")
        return False

    pwd_plain = getpass.getpass("Podaj hasło: ")
    if not pwd_plain:
        print("Hasło nie może być puste.")
        return False

    if check_user_exists(conn, login):
        print("Użytkownik o takim loginie już istnieje.")
        return False

    now = datetime.utcnow()
    if insert_user(conn, login, pwd_plain, now):
        print(f"Użytkownik '{login}' został zarejestrowany.")
        return True
    else:
        print("Błąd podczas rejestracji.")
        return False

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
        print("3. Wyjdz z programu")

        choice = input("Wybierz opcje (1-3): ").strip()

        if choice == "1":
            if menu_login():
                print("Zalogowano pomyslnie.")
                break
        elif choice == "2":
            menu_registration()
        elif choice == "3":
            print("Zamykanie programu...")
            sys.exit()
        else:
            print("Niepoprawny wybor, sproboj ponownie.")

if __name__ == "__main__":
    main_menu()