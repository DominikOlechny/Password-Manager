

import sys
from getpass import getpass

import pyodbc

from db.tableusers_insertandverify import create_user, verify_user


def prompt_credentials(*, confirm_password: bool = False) -> tuple[str, str] | None:
    """Zbiera dane logowania i hasło od użytkownika CLI."""
    login = input("Login: ").strip()
    if not login:
        print("\n[!] Login nie może być pusty.\n")
        return None

    password = getpass("Hasło: ")
    if not password:
        print("\n[!] Hasło nie może być puste.\n")
        return None

    if confirm_password:
        repeat = getpass("Powtórz hasło: ")
        if password != repeat:
            print("\n[!] Podane hasła nie są identyczne.\n")
            return None

    return login, password


def register_user() -> None:
    """Obsługuje proces rejestracji użytkownika."""
    credentials = prompt_credentials(confirm_password=True)
    if credentials is None:
        return

    login, password = credentials

    try:
        create_user(login=login, secured_pwd=password.encode("utf-8"))
    except pyodbc.IntegrityError:
        print("\n[!] Użytkownik o podanym loginie już istnieje.\n")
    except pyodbc.Error as exc:
        print(f"\n[!] Błąd podczas rejestracji: {exc}.\n")
    else:
        print("\n[+] Użytkownik został zarejestrowany pomyślnie.\n")


def login_user() -> None:
    """Obsługuje proces logowania użytkownika."""
    credentials = prompt_credentials(confirm_password=False)
    if credentials is None:
        return

    login, password = credentials

    try:
        exists = verify_user(login=login, secured_pwd=password.encode("utf-8"))
    except pyodbc.Error as exc:
        print(f"\n[!] Błąd podczas logowania: {exc}.\n")
        return

    if exists:
        print("\n[+] Logowanie zakończone sukcesem.\n")
    else:
        print("\n[!] Nieprawidłowy login lub hasło.\n")


def main() -> None:
    """Prosty interfejs wiersza poleceń dla menadżera haseł."""
    while True:
        print("=" * 40)
        print("Menadżer haseł - menu główne")
        print("=" * 40)
        print("1. Zarejestruj nowego użytkownika")
        print("2. Zaloguj użytkownika")
        print("3. Wyjdź")
        print("Q. Wyjdź")

        choice = input("\nWybierz opcję: ").strip()

        if choice == "1":
            register_user()
        elif choice == "2":
            login_user()
        elif choice in {"3", "q", "Q"}:
            print("\nDo zobaczenia!\n")
            return
        else:
            print("\n[!] Nieznana opcja, spróbuj ponownie.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nZatrzymano przez użytkownika.")
        sys.exit(0)