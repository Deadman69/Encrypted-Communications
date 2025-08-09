# Encrypted Messaging App

This application allows for secure communication using **end-to-end encryption** through the **NaCl** algorithm with the use of public and private keys. The application consists of two main parts: the server and the client.

## Overview

The application uses a simple architecture with a server that stores encrypted messages and a client that allows users to send and receive messages securely.

### Features:

* **End-to-end encryption**: Messages are encrypted on the client-side using the recipient's public key and are decrypted only on their device with their private key.
* **Secure Mode**: Messages are deleted after being read to ensure confidentiality.
* **User Interface (UI)**: The application features a graphical user interface (GUI) built with Tkinter, which allows users to start conversations, send messages, and interact with the server.

---

## Installation

### Prerequisites

Ensure you have **Python 3.x** installed on your system. You will also need to install a few Python libraries, which can be found in the `requirements.txt` file.

### Dependencies

1. Clone or download the repository.
2. Create and activate a virtual environment:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows, use 'venv\Scripts\activate'
   ```
3. Install the required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

---

## Running the Application

### 1. **Start the Server**

The server stores encrypted messages and handles requests to send and retrieve messages.

Run the following command to start the server:

```bash
cd server
py ./server.py
```

The server will run on `http://localhost:8000` by default. Ensure that the server is running properly before starting the client.

### 2. **Start the Client**

The client allows you to send and receive encrypted messages. Run the following command to start the client:

```bash
cd client
py ./client.py
```

The client will open a graphical window. You can enter messages, select a recipient by entering the recipient's public key, and send encrypted messages.

---

## Usage

### **Public and Private Keys**

Encryption relies on **Ed25519** key pairs. Each user must have a pair of keys (private and public). If you don't already have keys, the application will generate a pair of keys for you the first time you run it, and save them in the `keys.json` file.

* **Public key**: Used to encrypt messages. Every user should share their public key with others.
* **Private key**: Used to decrypt received messages. The private key should never be shared.

### **Secure Mode**

In **Secure Mode**, messages are automatically deleted after they are read. This mode guarantees that no sensitive data is left on the client after the conversation.

1. **Classic Mode**: Messages are retained after they are read.
2. **Secure Mode**: Messages are automatically deleted after they are read.

To activate Secure Mode, select it in the client application.

---

## Configuration

The configuration of the application is managed through the `config.json` file. You can configure parameters such as the server URL, polling interval, and language of the interface.

Example `config.json`:

```json
{
    "server_url": "http://localhost:8000",
    "polling_interval": 5,
    "language": "en"
}
```

### Languages

The app supports multiple languages. The default translation file is in English (`en.json`), but you can easily add other languages by creating a new JSON file in the `lang/` folder.

Example `en.json` file:

```json
{
    "select_mode": "Select a mode",
    "mode_classic": "Classic Mode",
    "mode_secure": "Secure Mode",
    "new_conversation": "New Conversation",
    "manual_poll": "Poll Manually",
    "server_online": "Server: Online",
    "server_offline": "Server: Offline",
    "error_no_conversation": "No active conversation.",
    "error_server": "Server error"
}
```

You can change the language via a dropdown menu in the client application.

---

## Troubleshooting

If you encounter issues, check the following:

* Ensure that the server is running before launching the client.
* Make sure you have generated a key pair for each user and that you are correctly sharing the public keys.
* If the server is offline, you will see the message "Server: Offline" in the client interface.

### **Common Errors**:

* **Server error**: This error occurs when there is an issue connecting to the server (server offline or network issue).
* **No active conversation**: You need to start a conversation with a contact before sending messages.

---

## Security

The application uses **NaCl (Ed25519)** encryption to ensure that only the recipient of a message can decrypt it. All communications between the client and server are encrypted, and messages are stored in an encrypted form on the server.

In **Secure Mode**, messages are automatically deleted from the client after being read, adding an extra layer of security.

---

## Authors

This project was developed by \[Your Name]. You can contact me via \[your email address].

---

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

---

### Note:

The **Secure Mode** is designed for use cases where maximum confidentiality is required. However, it's important to understand the limitations of deleted messages and their local storage.
