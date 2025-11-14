import json
import os
import hashlib
import secrets
import re
from datetime import datetime

DB_FILE = "users.json"
LOG_FILE = "access.log"

# --- Fonctions utilitaires ---
def load_db():
    if not os.path.exists(DB_FILE):
        return {}
    with open(DB_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_db(db):
    with open(DB_FILE, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=4, ensure_ascii=False)

def log_event(username, event):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} | {username} | {event}\n")

def hash_pwd(pwd, salt):
    return hashlib.sha256((salt + pwd).encode()).hexdigest()

def check_password_strength(pwd):
    if len(pwd) < 8:
        return False
    if not re.search(r"[A-Z]", pwd):
        return False
    if not re.search(r"[a-z]", pwd):
        return False
    if not re.search(r"[0-9]", pwd):
        return False
    if not re.search(r"[^\w]", pwd):
        return False
    return True

# --- Gestion des utilisateurs ---
def create_user(username, pwd, role="user"):
    db = load_db()
    if username in db:
        return False, "Utilisateur déjà existant."
    if not check_password_strength(pwd):
        return False, "Mot de passe trop faible."
    salt = secrets.token_hex(8)
    db[username] = {"hash": hash_pwd(pwd, salt), "salt": salt, "role": role}
    save_db(db)
    log_event(username, "Compte créé")
    return True, "Utilisateur créé avec succès."

def authenticate_user(username, pwd):
    db = load_db()
    if username not in db:
        log_event(username, "Échec connexion - inconnu")
        return False, "Utilisateur inconnu."
    user = db[username]
    if user["hash"] != hash_pwd(pwd, user["salt"]):
        log_event(username, "Échec connexion - mot de passe incorrect")
        return False, "Mot de passe incorrect."
    log_event(username, "Connexion réussie")
    return True, "Connexion réussie."

def change_password(username, new_pwd):
    db = load_db()
    if username not in db:
        return False, "Utilisateur inconnu."
    if not check_password_strength(new_pwd):
        return False, "Mot de passe trop faible."
    salt = secrets.token_hex(8)
    db[username]["hash"] = hash_pwd(new_pwd, salt)
    db[username]["salt"] = salt
    save_db(db)
    log_event(username, "Mot de passe modifié")
    return True, "Mot de passe mis à jour."

def delete_user(username, requester):
    db = load_db()
    if requester not in db or db[requester]["role"] != "admin":
        return False, "Seul un admin peut supprimer un utilisateur."
    if username not in db:
        return False, "Utilisateur introuvable."
    del db[username]
    save_db(db)
    log_event(username, f"Supprimé par {requester}")
    return True, "Utilisateur supprimé."

# --- Interface ---
def main_menu():
    while True:
        print("\n1 = Créer un compte")
        print("2 = Se connecter")
        print("3 = Quitter")
        choice = input("Choix : ")
        
        if choice == "1":
            u = input("Nom : ")
            p = input("Mot de passe : ")
            role = input("Rôle (user/admin) [user]: ") or "user"
            ok, msg = create_user(u, p, role)
            print(msg)
            
        elif choice == "2":
            u = input("Nom : ")
            p = input("Mot de passe : ")
            ok, msg = authenticate_user(u, p)
            print(msg)
            if ok:
                user_session(u)
                
        elif choice == "3":
            break
        else:
            print("Choix invalide.")

def user_session(username):
    db = load_db()
    role = db[username]["role"]
    while True:
        print(f"\nSession : {username} ({role})")
        print("1 = Changer mot de passe")
        if role == "admin":
            print("2 = Supprimer un utilisateur")
        print("0 = Déconnexion")
        choice = input("Choix : ")
        
        if choice == "1":
            new_pwd = input("Nouveau mot de passe : ")
            ok, msg = change_password(username, new_pwd)
            print(msg)
        elif choice == "2" and role == "admin":
            target = input("Nom de l'utilisateur à supprimer : ")
            ok, msg = delete_user(target, username)
            print(msg)
        elif choice == "0":
            print("Déconnexion...")
            break
        else:
            print("Choix invalide.")

if __name__ == "__main__":
    main_menu()
