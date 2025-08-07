import os
import tkinter as tk
from tkinter import simpledialog, messagebox
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import HexEncoder
import requests
import json
import time
import threading
import random

# Chemin du fichier où on stocke les clés
KEY_FILE = "keys.json"

# Fonction pour générer une clé publique et une clé privée
def generate_keys():
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    return private_key, public_key

# Fonction pour charger les clés depuis un fichier
def load_keys():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'r') as f:
            data = json.load(f)
            private_key = PrivateKey(data['private_key'], encoder=HexEncoder)
            public_key = PublicKey(data['public_key'], encoder=HexEncoder)
            return private_key, public_key
    else:
        # Si le fichier n'existe pas, générer une nouvelle paire de clés
        private_key, public_key = generate_keys()
        save_keys(private_key, public_key)
        return private_key, public_key

# Fonction pour sauvegarder les clés dans un fichier
def save_keys(private_key, public_key):
    with open(KEY_FILE, 'w') as f:
        data = {
            "private_key": private_key.encode(encoder=HexEncoder).decode(),
            "public_key": public_key.encode(encoder=HexEncoder).decode()
        }
        json.dump(data, f)

# Fonction pour chiffrer un message avec la clé publique du destinataire
def encrypt_message(message, recipient_public_key, sender_private_key):
    box = Box(sender_private_key, recipient_public_key)
    encrypted = box.encrypt(message.encode('utf-8'))
    return encrypted

# Fonction pour déchiffrer un message avec la clé privée de l'utilisateur
def decrypt_message(encrypted_message, sender_public_key, receiver_private_key):
    if isinstance(encrypted_message, str):  # Si c'est une chaîne (hex)
        encrypted_message = bytes.fromhex(encrypted_message)  # Convertir de l'hexadécimal en bytes
    box = Box(receiver_private_key, sender_public_key)
    decrypted = box.decrypt(encrypted_message)  # Déchiffre directement les bytes
    return decrypted.decode('utf-8')  # Puis déchiffrer les données

# Fonction pour envoyer un message au serveur
def send_message_to_server(encrypted_message, sender_public_key, expiration_time):
    encrypted_message_hex = encrypted_message.hex()
    data = {
        "encrypted_message": encrypted_message_hex,
        "sender": sender_public_key.encode(encoder=HexEncoder).decode(),
        "expiration_time": expiration_time
    }
    response = requests.post("http://localhost:8000/put/", json=data)
    if response.status_code != 200:
        print("Erreur :", response.status_code)
        print("Détails :", response.text)
    return response

class Conversation:
    def __init__(self, contact_public_key, mode='classique'):
        self.contact_public_key = contact_public_key
        self.messages = []
        self.mode = mode
        self.message_ids = set()
    
    def add_message(self, message, encrypted=True, message_id=None):
        if encrypted:
            self.messages.append({'message': message, 'encrypted': True, 'message_id': message_id})
        else:
            self.messages.append({'message': message, 'encrypted': False, 'message_id': message_id})

    def get_messages(self):
        return self.messages

    def clear_messages(self):
        if self.mode == 'securise':
            self.messages = []

    def is_message_received(self, message_id):
        return message_id in self.message_ids

    def mark_message_as_received(self, message_id):
        self.message_ids.add(message_id)

class MessengerApp:
    def __init__(self, root, sender_private_key, sender_public_key):
        self.root = root
        self.sender_private_key = sender_private_key
        self.sender_public_key = sender_public_key
        self.conversations = {}
        self.current_conversation = None
        self.root.title("Messagerie Chiffrée")
        self.root.geometry("500x800")

        # Créer un cadre principal qui va se redimensionner avec la fenêtre
        self.frame = tk.Frame(root)
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Mode
        self.mode_var = tk.StringVar(value="classique")
        self.label = tk.Label(root, text="Sélectionnez un mode", font=("Helvetica", 14))
        self.label.pack(pady=5)

        # Radio boutons pour sélectionner le mode
        self.radio_classique = tk.Radiobutton(root, text="Mode Classique", variable=self.mode_var, value="classique")
        self.radio_classique.pack(pady=5, fill=tk.X)  # "fill=tk.X" pour étendre horizontalement

        self.radio_securise = tk.Radiobutton(root, text="Mode Sécurisé", variable=self.mode_var, value="securise")
        self.radio_securise.pack(pady=5, fill=tk.X)

        # Bouton pour démarrer une nouvelle conversation
        self.start_button = tk.Button(root, text="Nouvelle Conversation", command=self.new_conversation)
        self.start_button.pack(pady=5, fill=tk.X)

        # Bouton pour "poller" manuellement
        self.poll_button = tk.Button(root, text="Poller Manuellement", command=self.poll_messages)
        self.poll_button.pack(pady=5, fill=tk.X)

        # Fenêtre de chat qui doit se redimensionner
        self.chat_window = tk.Listbox(self.frame, height=20, width=60)
        self.chat_window.pack(fill=tk.BOTH, expand=True)  # Expanding pour occuper l'espace libre

        # Zone de texte pour envoyer un message
        self.text_entry = tk.Entry(root, width=50)
        self.text_entry.pack(pady=5, fill=tk.X)

        # Bouton pour envoyer le message
        self.send_button = tk.Button(root, text="Envoyer", command=self.send_message)
        self.send_button.pack(pady=5)

        # Label pour afficher le statut du serveur
        self.server_status_label = tk.Label(root, text="Serveur : Hors ligne", fg="red", font=("Helvetica", 12))
        self.server_status_label.pack(pady=5)

        # Démarrer le thread de polling
        self.poll_thread = threading.Thread(target=self.poll_messages_periodically)
        self.poll_thread.daemon = True
        self.poll_thread.start()
        
    def new_conversation(self):
        contact_public_key_str = simpledialog.askstring("Clé Publique", "Entrez la clé publique du destinataire:")
        contact_public_key = PublicKey(contact_public_key_str, encoder=HexEncoder)
        self.current_conversation = Conversation(contact_public_key, self.mode_var.get())
        self.conversations[contact_public_key_str] = self.current_conversation
        self.chat_window.delete(0, tk.END)
        self.chat_window.insert(tk.END, f"Conversation avec {contact_public_key_str}")

    def send_message(self):
        message = self.text_entry.get()
        if not message:
            return
        if self.current_conversation is None:
            messagebox.showerror("Erreur", "Aucune conversation active.")
            return
        
        recipient_public_key = self.current_conversation.contact_public_key
        encrypted_message = encrypt_message(message, recipient_public_key, self.sender_private_key)
        
        expiration_time = int(time.time()) + 60  # L'expiration est dans 60 secondes
        send_message_to_server(encrypted_message, self.sender_public_key, expiration_time)
        
        self.current_conversation.add_message(message, encrypted=False)
        self.chat_window.insert(tk.END, f"Vous : {message}")
        self.text_entry.delete(0, tk.END)

    def poll_messages(self):
        if self.current_conversation is None:
            messagebox.showerror("Erreur", "Aucune conversation active.")
            return
        
        contact_public_key = self.current_conversation.contact_public_key
        try:
            response = requests.post("http://localhost:8000/get/")  # Récupérer les messages
            if response.status_code == 200:
                self.server_status_label.config(text="Serveur : En ligne", fg="green")
                data = response.json()
                for msg in data.get("messages", []):
                    message_id = msg.get('id')  # Supposons que chaque message ait un ID unique
                    if not self.current_conversation.is_message_received(message_id):
                        encrypted_message = msg['encrypted_message']
                        decrypted_message = decrypt_message(encrypted_message, contact_public_key, self.sender_private_key)
                        
                        # Récupérer la clé publique 'sender' et la convertir en format hexadécimal lisible
                        sender = msg.get('sender')
                        if isinstance(sender, str):
                            sender = bytes.fromhex(sender)  # Si c'est une chaîne hexadécimale, on la convertit en bytes
                        sender_readable = HexEncoder.encode(sender).decode('utf-8')  # Convertir en hex et décoder en chaîne

                        # Troncature du nom (prendre les 4 premiers et 4 derniers caractères + "...")
                        if len(sender_readable) > 8:
                            sender_readable = sender_readable[:4] + "..." + sender_readable[-4:]

                        if sender != self.sender_public_key:  # Si l'expéditeur n'est pas soi-même
                            self.current_conversation.add_message(decrypted_message, encrypted=False, message_id=message_id)
                            self.chat_window.insert(tk.END, f"De {sender_readable}: {decrypted_message}")
                        else:
                            # Si le message vient de soi-même, afficher sous forme de "Vous : XXXXX"
                            self.current_conversation.add_message(decrypted_message, encrypted=False, message_id=message_id)
                            self.chat_window.insert(tk.END, f"Vous : {decrypted_message}")
                        
                        self.current_conversation.mark_message_as_received(message_id)
                
                if self.current_conversation.mode == 'securise':
                    self.current_conversation.clear_messages()
            else:
                self.server_status_label.config(text="Serveur : Hors ligne", fg="red")
        except requests.exceptions.RequestException:
            self.server_status_label.config(text="Serveur : Hors ligne", fg="red")

    def poll_messages_periodically(self):
        while True:
            if self.current_conversation:
                self.poll_messages()
            time.sleep(5 + 5 * random.random())  # 5-10 secondes


# Lancement de l'application
if __name__ == "__main__":
    sender_private_key, sender_public_key = load_keys()  # Charge les clés persistantes
    root = tk.Tk()
    app = MessengerApp(root, sender_private_key, sender_public_key)
    root.mainloop()
