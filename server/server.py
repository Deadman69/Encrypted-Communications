from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3
import os
import json
import time
from cryptography.hazmat.primitives import hashes

app = FastAPI()

DATABASE = "messages.db"

# Création de la base de données si elle n'existe pas
if not os.path.exists(DATABASE):
    try:
        # Connexion à la base de données SQLite
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Création de la table messages
        cursor.execute('''CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            encrypted_message TEXT,
            sender TEXT,
            expiration_time INTEGER)''')
        conn.commit()
        print("Table 'messages' créée avec succès.")

        # Vérifier que la table a bien été créée
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages';")
        if cursor.fetchone():
            print("La table 'messages' existe bien.")
        else:
            print("Erreur : La table 'messages' n'a pas pu être créée.")
        
        conn.close()
    except sqlite3.Error as e:
        print(f"Erreur SQLite : {e}")

class Message(BaseModel):
    encrypted_message: str
    sender: str  # Ajouter un champ pour l'expéditeur
    expiration_time: int  # expiration en secondes depuis l'epoch

@app.post("/put/")
async def put_message(message: Message):
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO messages (encrypted_message, sender, expiration_time) 
                          VALUES (?, ?, ?)''', 
                       (message.encrypted_message, message.sender, message.expiration_time))
        conn.commit()
        conn.close()
        return {"status": "Message stored"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Server error: " + str(e))

@app.post("/get/")
async def get_messages():
    current_time = int(time.time())
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM messages WHERE expiration_time > ?', (current_time,))
        messages = cursor.fetchall()
        conn.close()
        if messages:
            # Inclure 'sender' dans la réponse
            return {"messages": [{"id": msg[0], "encrypted_message": msg[1], "sender": msg[2]} for msg in messages]}
        return {"messages": []}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Server error: " + str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
