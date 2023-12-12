import re
import hashlib
import json
import random
import string

def check_password_requirements(password):
    if len(password) < 8:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char in '!@#$%^&*' for char in password):
        return False
    return True

def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode('utf-8'))
    return sha256.hexdigest()

def save_password(username, password, hashed_password, stored_passwords):
    stored_passwords[username] = hashed_password
    with open('passwords.json', 'w') as file:
        json.dump(stored_passwords, file)
    print("Mot de passe enregistré avec succès.")

def generate_random_password():
    characters = string.ascii_letters + string.digits + '!@#$%^&*'
    return ''.join(random.choice(characters) for _ in range(12))

def show_saved_passwords(stored_passwords):
    print("Mots de passe enregistrés :")
    for user, hashed_pass in stored_passwords.items():
        print(f"Username: {user}, Hashed Password: {hashed_pass}")

def main():
    try:
        with open('passwords.json', 'r') as file:
            stored_passwords = json.load(file)
    except FileNotFoundError:
        stored_passwords = {}

    username = input("Entrez votre nom d'utilisateur : ")

    while True:
        password = input("Entrez votre mot de passe : ")
        if check_password_requirements(password):
            hashed_password = hash_password(password)
            save_password(username, password, hashed_password, stored_passwords)
            break
        else:
            print("Le mot de passe ne respecte pas les exigences. Veuillez réessayer.")

    show_saved_passwords(stored_passwords)

    # Bonus: Comparaison pour éviter les doublons
    if username in stored_passwords:
        old_password = input("Voulez-vous voir le mot de passe que vous avez déjà enregistré ? (O/N) : ")
        if old_password.lower() == 'o':
            print(f"Le mot de passe enregistré pour {username} est : {stored_passwords[username]}")

    # Bonus: Générer un nouveau mot de passe aléatoire
    new_password = generate_random_password()
    new_username = input("Entrez un nouveau nom d'utilisateur : ")

    while new_username in stored_passwords:
        new_username = input("Nom d'utilisateur déjà pris. Entrez un nouveau nom d'utilisateur : ")

    hashed_new_password = hash_password(new_password)
    save_password(new_username, new_password, hashed_new_password, stored_passwords)
    print(f"Nouveau mot de passe généré pour {new_username} : {new_password}")

if __name__ == "__main__":
    main()
