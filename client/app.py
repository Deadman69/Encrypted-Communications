import sys, os, json, time, threading, random, mimetypes, base64, io, uuid, webbrowser, hashlib, binascii
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional, List, Dict, Tuple
from PIL import Image, ImageTk, ImageFile

Image.MAX_IMAGE_PIXELS = 100_000_000  # ~100 MP cap
ImageFile.LOAD_TRUNCATED_IMAGES = False

from nacl.public import PrivateKey, PublicKey
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from nacl.signing import VerifyKey as _VerifyKey
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

from security import canonical_dumps, signed_post, encrypt_for, decrypt_with, PoWHelper, HttpClient
from interface import (
    I18n, ContactDialog, IdentityDialog, IdentitiesManager, ContactsManager,
    SelectContactDialog, SettingsDialog
)

# ===== files & config =====
CONFIG_FILE   = "config.json"
IDENTS_FILE   = "identities.json"
CONTACTS_FILE = "contacts.json"
VAULT_FILE    = "conversations.vault"
VAULT_KEY_FILE= "vault.key"

LOCK_FILE = "master.lock"
ENC_MAGIC = b"EMSGENC1"

REPO_URL    = "https://github.com/Deadman69/Encrypted-Communications"
LICENSE_URL = "https://www.gnu.org/licenses/agpl-3.0.en.html"

DEFAULT_CONFIG = {
    "server_url": "http://localhost:8000",
    "language": "en",
    "secure_mode": False,
    # demander de définir un mot de passe quand aucun n'est défini
    "ask_set_password": True,
    # network
    "use_tor": True,
    "socks_proxy": "socks5h://127.0.0.1:9050",
    # polling
    "polling_base": 5.0,
    "polling_jitter": 3.0
}

class CryptoManager:
    """
    Chiffre/déchiffre des JSON (contacts, identités, conversations) avec une clé maître optionnelle.
    - master_key: 32 bytes (None => on écrit/lit en clair pour compat ascendante)
    - on dérive des sous-clés par contexte: blake2b(key=master_key, data=context)
    - format chiffré: ENC_MAGIC + SecretBox(subkey).encrypt(json_bytes)
    """
    def __init__(self, master_key: Optional[bytes]):
        self.master_key = master_key

    def _subkey(self, context: str) -> Optional[bytes]:
        if not self.master_key:
            return None
        h = hashlib.blake2b(context.encode("utf-8"), key=self.master_key, digest_size=32)
        return h.digest()

    def save_json(self, path: str, obj, context: str):
        data = json.dumps(obj, separators=(',', ':'), ensure_ascii=False).encode("utf-8")
        sub = self._subkey(context)
        if not sub:
            # clair (compat)
            with open(path, "w", encoding="utf-8") as f:
                f.write(data.decode("utf-8"))
            return
        ct = SecretBox(sub).encrypt(data)  # nonce aléatoire inclus
        with open(path, "wb") as f:
            f.write(ENC_MAGIC + ct)

    def load_json(self, path: str, default, context: str):
        if not os.path.exists(path):
            return default
        with open(path, "rb") as f:
            raw = f.read()
        if raw.startswith(ENC_MAGIC):
            sub = self._subkey(context)
            if not sub:
                raise RuntimeError("File is encrypted but no password provided")
            enc = raw[len(ENC_MAGIC):]
            data = SecretBox(sub).decrypt(enc)
            return json.loads(data.decode("utf-8"))
        else:
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception as e:
                raise

def bundle_path(*parts):
    base = getattr(sys, "_MEIPASS", os.path.dirname(__file__))
    return os.path.join(base, *parts)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE,"r", encoding="utf-8") as f:
            cfg = json.load(f)
        # backfill defaults
        for k,v in DEFAULT_CONFIG.items():
            cfg.setdefault(k, v)
        return cfg
    with open(CONFIG_FILE,"w", encoding="utf-8") as f:
        json.dump(DEFAULT_CONFIG,f,indent=4, ensure_ascii=False)
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    with open(CONFIG_FILE,"w", encoding="utf-8") as f:
        json.dump(cfg,f,indent=4, ensure_ascii=False)

# ===== models =====
class Identity:
    def __init__(self, id_: str, name: str, box_sk_hex: str, box_pk_hex: str, sign_sk_hex: str, sign_pk_hex: str):
        self.id = id_
        self.name = name
        self.box_sk = PrivateKey(box_sk_hex, encoder=HexEncoder)
        self.box_pk = PublicKey(box_pk_hex, encoder=HexEncoder)
        self.sign_sk = SigningKey(bytes.fromhex(sign_sk_hex))
        self.sign_pk = _VerifyKey(bytes.fromhex(sign_pk_hex))

    @property
    def box_pub_hex(self):
        return self.box_pk.encode(encoder=HexEncoder).decode()

    @property
    def sign_pub_hex(self):
        return self.sign_pk.encode().hex()

    @staticmethod
    def generate(name: str) -> "Identity":
        box_sk = PrivateKey.generate(); box_pk = box_sk.public_key
        sign_sk = SigningKey.generate(); sign_pk = sign_sk.verify_key
        return Identity(
            id_=str(uuid.uuid4()),
            name=name,
            box_sk_hex=box_sk.encode(encoder=HexEncoder).decode(),
            box_pk_hex=box_pk.encode(encoder=HexEncoder).decode(),
            sign_sk_hex=sign_sk.encode().hex(),
            sign_pk_hex=sign_pk.encode().hex()
        )

    @staticmethod
    def from_material(name: str,
                      box_sk_hex: str,
                      box_pk_hex: Optional[str],
                      sign_sk_hex: str,
                      sign_pk_hex: Optional[str]) -> "Identity":
        if not box_pk_hex:
            sk = PrivateKey(box_sk_hex, encoder=HexEncoder)
            box_pk_hex = sk.public_key.encode(encoder=HexEncoder).decode()
        if not sign_pk_hex:
            sk = SigningKey(bytes.fromhex(sign_sk_hex))
            sign_pk_hex = sk.verify_key.encode().hex()

        def _is_hex_32(s):
            try: return s and len(s)==64 and int(s,16) >= 0
            except: return False
        if not (_is_hex_32(box_sk_hex) and _is_hex_32(box_pk_hex) and _is_hex_32(sign_sk_hex) and _is_hex_32(sign_pk_hex)):
            raise ValueError("Invalid key material (must be 32-byte hex)")

        return Identity(
            id_=str(uuid.uuid4()),
            name=name,
            box_sk_hex=box_sk_hex,
            box_pk_hex=box_pk_hex,
            sign_sk_hex=sign_sk_hex,
            sign_pk_hex=sign_pk_hex
        )

    def to_dict(self):
        return {
            "id": self.id, "name": self.name,
            "box_private_key": self.box_sk.encode(encoder=HexEncoder).decode(),
            "box_public_key":  self.box_pub_hex,
            "sign_private_key": self.sign_sk.encode().hex(),
            "sign_public_key":  self.sign_pub_hex
        }

class IdentityStore:
    def __init__(self, path=IDENTS_FILE, bootstrap_default: bool = True, crypto: Optional[CryptoManager]=None):
        self.path = path
        self.bootstrap_default = bootstrap_default
        self.crypto = crypto or CryptoManager(None)
        self.identities: Dict[str, Identity] = {}
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                arr = self.crypto.load_json(self.path, default=[], context="identities")
            except Exception:
                # fallback clair
                with open(self.path, "r", encoding="utf-8") as f:
                    arr = json.load(f)
        else:
            arr = [Identity.generate("Default Identity").to_dict()] if self.bootstrap_default else []
            self.save_arr(arr)
        self.identities = {d["id"]: Identity(
            id_=d["id"], name=d["name"],
            box_sk_hex=d["box_private_key"], box_pk_hex=d["box_public_key"],
            sign_sk_hex=d["sign_private_key"], sign_pk_hex=d["sign_public_key"]
        ) for d in arr}

    def save_arr(self, arr):
        self.crypto.save_json(self.path, arr, context="identities")

    def save(self):
        arr = [idn.to_dict() for idn in self.identities.values()]
        self.save_arr(arr)

    def add(self, name: str) -> Identity:
        idn = Identity.generate(name)
        self.identities[idn.id] = idn
        self.save()
        return idn

    def add_from_material(self, name: str, *,
                          box_sk_hex: str, box_pk_hex: Optional[str],
                          sign_sk_hex: str, sign_pk_hex: Optional[str]) -> Identity:
        idn = Identity.from_material(name, box_sk_hex, box_pk_hex, sign_sk_hex, sign_pk_hex)
        self.identities[idn.id] = idn
        self.save()
        return idn

    def replace_keys(self, id_: str, *, box_sk_hex: str, box_pk_hex: str, sign_sk_hex: str, sign_pk_hex: str):
        idn = self.identities[id_]
        idn.box_sk = PrivateKey(box_sk_hex, encoder=HexEncoder)
        idn.box_pk = PublicKey(box_pk_hex, encoder=HexEncoder)
        idn.sign_sk = SigningKey(bytes.fromhex(sign_sk_hex))
        idn.sign_pk = _VerifyKey(bytes.fromhex(sign_pk_hex))
        self.save()

    def rename(self, id_: str, new_name: str):
        self.identities[id_].name = new_name; self.save()

    def delete(self, id_: str):
        if id_ in self.identities:
            del self.identities[id_]; self.save()

    def list(self) -> List[Identity]:
        return list(self.identities.values())

class ContactsStore:
    def __init__(self, path=CONTACTS_FILE, crypto: Optional[CryptoManager]=None):
        self.path = path
        self.crypto = crypto or CryptoManager(None)
        self._arr: List[Dict] = []
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                self._arr = self.crypto.load_json(self.path, default=[], context="contacts")
            except Exception:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._arr = json.load(f)
        else:
            self._arr = []; self.save()

    def save(self):
        self.crypto.save_json(self.path, self._arr, context="contacts")

    def items(self) -> List[Dict]:
        return list(self._arr)

    def add(self, name: str, pub_hex: str, sign_pub_hex: str, identity_id: str):
        """Add a contact and pin BOTH encryption and signing public keys."""
        self._arr.append({
            "name": name,
            "pub_hex": pub_hex,
            "sign_pub_hex": sign_pub_hex,
            "identity_id": identity_id
        })
        self.save()

    def update(self, idx: int, name: str, pub_hex: str, sign_pub_hex: str, identity_id: str):
        """Update contact record; keep signing key pinning consistent."""
        self._arr[idx] = {
            "name": name,
            "pub_hex": pub_hex,
            "sign_pub_hex": sign_pub_hex,
            "identity_id": identity_id
        }
        self.save()

    def delete(self, idx: int):
        del self._arr[idx]; self.save()

    def find_by_pub(self, pub_hex: str) -> Optional[Dict]:
        """Find a contact by its encryption pubkey."""
        for c in self._arr:
            if c["pub_hex"] == pub_hex:
                return c
        return None
    
    def find_by_sign(self, sign_hex: str) -> Optional[Dict]:
        """Find a contact by its signing pubkey (rarely used, kept for completeness)."""
        for c in self._arr:
            if c.get("sign_pub_hex") == sign_hex:
                return c
        return None

class Conversation:
    def __init__(self, ident_id: str, ident_name: str, contact_name: str, contact_pub_hex: str):
        self.identity_id = ident_id
        self.identity_name = ident_name
        self.contact_name = contact_name
        self.contact_pub_hex = contact_pub_hex
        self.messages = []
        self._image_refs = []
        self.unread = 0

        # Anti-replay: keep a small moving window of recent payload hashes
        import collections
        self.replay_recent = collections.deque(maxlen=500)
        # Helps pre-fill signing key when adding unknown contacts
        self._last_sender_sign_pub = None

# ===== app =====
class MessengerApp:
    def __init__(self, root):
        self.root = root
        # Avoid white empty window
        try:
            self.root.withdraw()
        except Exception:
            pass

        self.cfg = load_config()
        self.i18n = I18n(langs_dir=bundle_path("langs"), default_lang=self.cfg.get("language", "en"))
        self.tr = self.i18n.t

        self.crypto = CryptoManager(None)

        # Init password (can close app if closed)
        if not self.cfg.get("secure_mode", False):
            ok = self._init_password()
            if not ok:
                try: self.root.destroy()
                except Exception: pass
                return

        # secure mode: purge local storage except config
        if self.cfg.get("secure_mode", False):
            for p in (IDENTS_FILE, CONTACTS_FILE, VAULT_FILE, VAULT_KEY_FILE):
                try:
                    if os.path.exists(p): os.remove(p)
                except: pass

        # network client + PoW
        self.http = HttpClient(self.cfg.get("use_tor", True), self.cfg.get("socks_proxy","socks5h://127.0.0.1:9050"))
        self.pow  = PoWHelper(self.cfg["server_url"], self.http)

        # stores
        self.ident_store = IdentityStore(bootstrap_default=not self.cfg.get("secure_mode", False), crypto=self.crypto)
        self.contacts = ContactsStore(crypto=self.crypto)

        # state
        self.conversations: Dict[Tuple[str,str], Conversation] = {}
        self.current_conv: Optional[Conversation] = None
        self._current_key: Optional[Tuple[str,str]] = None
        self._index_to_key: List[Tuple[str,str]] = []
        self._seen_ids = set()
        self._busy = 0
        self._pending: Dict[str, threading.Event] = {}
        self._session_tokens: Dict[str, Tuple[str,int]] = {}

        self._history_loaded = False
        self._build_ui()
        self._show_loading_banner()
        threading.Thread(target=self._load_history_thread, daemon=True).start()

        self.root.after(80, self._on_history_loaded_tick)

        self._register_all_identities()
        self._refresh_conv_sidebar(select_key=self._current_key)
        self._start_poll_thread()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        try:
            self.root.deiconify()
        except Exception:
            pass

    def _scrypt_key(self, password: str, salt: bytes) -> bytes:
        pw = password.encode("utf-8")
        # Try multiple parameters (from stronger to most compatible)
        tries = [
            dict(n=2**15, r=8, p=1, maxmem=64*1024*1024),  # ~32 MiB required, we allow 64 MiB
            dict(n=2**14, r=8, p=1, maxmem=64*1024*1024),  # ~16 MiB
            dict(n=2**14, r=8, p=1, maxmem=0),             # no explicit memory limit
            dict(n=2**13, r=8, p=1, maxmem=0),             # ~8 MiB (last chance)
        ]
        last_err = None
        for params in tries:
            try:
                return hashlib.scrypt(pw, salt=salt, dklen=32, **params)
            except (ValueError, MemoryError) as e:
                last_err = e
                continue
        raise last_err or ValueError("scrypt failed")

    def _init_password(self) -> bool:
        """
        Initialise self.crypto.
        True  => continuer le lancement
        False => l'utilisateur a annulé (ou lock corrompu) -> quitter
        """
        from interface import PasswordDialog, AskSetPasswordDialog

        if os.path.exists(LOCK_FILE):
            # Déverrouillage
            try:
                with open(LOCK_FILE, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                salt = base64.b64decode(meta["salt"])
                box_hex = meta["box"]
            except Exception:
                messagebox.showerror(self.tr("pwd.unlock.title"), "Lock file corrupted.")
                return False

            while True:
                dlg = PasswordDialog(self.root, self.tr, mode="unlock")
                self.root.wait_window(dlg)
                if not dlg.result:
                    # Vide = annuler proprement
                    return False
                key = self._scrypt_key(dlg.result, salt)
                try:
                    SecretBox(key).decrypt(bytes.fromhex(box_hex))
                    self.crypto = CryptoManager(key)
                    return True
                except Exception:
                    messagebox.showerror(self.tr("pwd.unlock.title"), self.tr("pwd.bad"))
        else:
            # Aucun mot de passe : proposer d'en définir un (si activé dans la config)
            if self.cfg.get("ask_set_password", True):
                ask = AskSetPasswordDialog(self.root, self.tr)
                self.root.wait_window(ask)
                if ask.result and ask.result.get("dont_ask"):
                    self.cfg["ask_set_password"] = False
                    save_config(self.cfg)

                if ask.result and ask.result.get("set_now"):
                    # Création d'un nouveau mot de passe -> chiffrer immédiatement les fichiers existants
                    dlg = PasswordDialog(self.root, self.tr, mode="set")
                    self.root.wait_window(dlg)
                    if dlg.result:
                        salt = os.urandom(16)
                        key = self._scrypt_key(dlg.result, salt)
                        probe = SecretBox(key).encrypt(b"OK").hex()
                        with open(LOCK_FILE, "w", encoding="utf-8") as f:
                            json.dump(
                                {"ver": 1, "salt": base64.b64encode(salt).decode(), "box": probe},
                                f, indent=2
                            )
                        self.crypto = CryptoManager(key)
                        # <<< NOUVEAU : chiffrer immédiatement tout ce qui existe >>>
                        try:
                            self._encrypt_existing_data_files()
                        except Exception as e:
                            print("encrypt_existing_data_files error:", e)
                        return True
                    # Annule la création -> pas de mot de passe
                    self.crypto = CryptoManager(None)
                    return True

            # Cas « ne plus demander » ou refus : pas de mot de passe
            self.crypto = CryptoManager(None)
            return True
    
    def _encrypt_existing_data_files(self):
        """
        Chiffre sur place les fichiers locaux si actuellement en clair ou en ancien format.
        Nécessite self.crypto.master_key non nul (mot de passe défini).
        """
        if not getattr(self.crypto, "master_key", None):
            return

        def migrate_json_file(path: str, context: str, *, is_vault: bool = False):
            if not os.path.exists(path):
                return
            try:
                with open(path, "rb") as f:
                    raw = f.read()

                # Déjà au nouveau format chiffré ?
                if raw.startswith(ENC_MAGIC):
                    return

                obj = None

                # 1) Essayer en clair
                try:
                    obj = json.loads(raw.decode("utf-8"))
                except Exception:
                    obj = None

                # 2) Vault ancien format (SecretBox + VAULT_KEY_FILE)
                if obj is None and is_vault:
                    try:
                        box = SecretBox(self._vault_key())
                        dec = box.decrypt(raw)
                        obj = json.loads(dec.decode("utf-8"))
                        # On peut supprimer l’ancienne clé de vault
                        try:
                            if os.path.exists(VAULT_KEY_FILE):
                                os.remove(VAULT_KEY_FILE)
                        except Exception:
                            pass
                    except Exception:
                        obj = None

                if obj is None:
                    # Rien à migrer (fichier inconnu)
                    return

                # Réécriture chiffrée avec la master key
                self.crypto.save_json(path, obj, context=context)

            except Exception as e:
                print(f"encrypt_existing: erreur sur {path}: {e}")

        migrate_json_file(IDENTS_FILE,   "identities")
        migrate_json_file(CONTACTS_FILE, "contacts")
        migrate_json_file(VAULT_FILE,    "vault", is_vault=True)

    # ----- vault -----
    def _vault_key(self) -> bytes:
        if self.cfg.get("secure_mode", False):
            return hashlib.sha256(b"disabled").digest()
        if not os.path.exists(VAULT_KEY_FILE):
            with open(VAULT_KEY_FILE, "wb") as f: f.write(os.urandom(32))
        with open(VAULT_KEY_FILE, "rb") as f:
            raw = f.read()
        if len(raw) != SecretBox.KEY_SIZE:
            raw = hashlib.sha256(raw).digest()
        return raw

    def _purge_vault(self):
        for p in (VAULT_FILE, VAULT_KEY_FILE):
            try:
                if os.path.exists(p): os.remove(p)
            except: pass

    def _save_history(self):
        """Persist conversations; encrypt depending on CryptoManager configuration."""
        if self.cfg.get("secure_mode", False):
            # In secure mode, do not persist anything to disk.
            try:
                if os.path.exists(VAULT_FILE):
                    os.remove(VAULT_FILE)
            except Exception:
                pass
            return
        try:
            data = {
                "version": 1,
                "current_key": list(self._current_key) if self._current_key else None,
                "conversations": []
            }
            for key, conv in self.conversations.items():
                msgs = []
                for m in conv.messages:
                    m2 = dict(m)
                    # Store binary payloads as base64 lazily to keep JSON transportable
                    if "data" in m2 and isinstance(m2["data"], (bytes, bytearray)):
                        m2["data_b64"] = base64.b64encode(m2.pop("data")).decode()
                    msgs.append(m2)
                data["conversations"].append({
                    "key": list(key),
                    "identity_name": conv.identity_name,
                    "contact_name": conv.contact_name,
                    "contact_pub_hex": conv.contact_pub_hex,
                    "messages": msgs,
                    "unread": conv.unread,
                    # Persist anti-replay cache so restarts do not re-accept old payloads
                    "replay_recent": list(conv.replay_recent)
                })
            # Encrypted or clear depending on CryptoManager.master_key
            self.crypto.save_json(VAULT_FILE, data, context="vault")
        except Exception as e:
            print("save_history error:", e)

    def _load_history(self):
        """Load persisted conversations (supports legacy vault, then new format)."""
        if self.cfg.get("secure_mode", False):
            return
        if not os.path.exists(VAULT_FILE):
            return
        # Try new encrypted format first
        try:
            obj = self.crypto.load_json(VAULT_FILE, default=None, context="vault")
            if obj is None:
                return
        except Exception:
            # Legacy fallback (old SecretBox + VAULT_KEY_FILE layout)
            try:
                with open(VAULT_FILE, "rb") as f:
                    enc = f.read()
                box = SecretBox(self._vault_key())
                raw = box.decrypt(enc)
                obj = json.loads(raw.decode())
            except Exception as e:
                print("load_history legacy error:", e)
                return

        try:
            self._current_key = tuple(obj.get("current_key") or []) or None
            for rec in obj.get("conversations", []):
                key = tuple(rec["key"])
                conv = Conversation(
                    ident_id=key[0],
                    ident_name=rec.get("identity_name", ""),
                    contact_name=rec.get("contact_name", ""),
                    contact_pub_hex=rec.get("contact_pub_hex", key[1])
                )
                conv.unread = int(rec.get("unread", 0))
                # Restore anti-replay cache
                for h in rec.get("replay_recent", []):
                    try:
                        conv.replay_recent.append(h)
                    except Exception:
                        pass
                # Restore messages (lazy decode of data_b64 happens on render)
                for m in rec.get("messages", []):
                    conv.messages.append(dict(m))
                self.conversations[key] = conv
        except Exception as e:
            print("load_history parse error:", e)
    
    # ----- history ------
    def _show_loading_banner(self):
        try:
            self.chat_text.configure(state="normal")
            self.chat_text.delete("1.0", "end")
            self.chat_text.insert("end", self.tr("loading.history") + "\n", ("meta_in",))
            self.chat_text.configure(state="disabled")
        except Exception:
            pass

    def _load_history_thread(self):
        try:
            self._load_history()
        except Exception as e:
            print("load_history (thread) error:", e)
        finally:
            self._history_loaded = True

    def _on_history_loaded_tick(self):
        if self._history_loaded:
            self._refresh_conv_sidebar(select_key=self._current_key)
        else:
            self.root.after(80, self._on_history_loaded_tick)


    # ----- register -----
    def _register_identity(self, idn):
        try:
            url = self.cfg["server_url"].rstrip("/") + "/register"
            signed_post(self.http, url, {"box_pub": idn.box_pub_hex}, idn.sign_sk, idn.sign_pub_hex)
        except Exception as e:
            print("Register failed for", idn.name, e)

    def _register_all_identities(self):
        for idn in self.ident_store.list():
            self._register_identity(idn)

    # ----- UI -----
    def _build_ui(self):
        self.root.title(self.tr("app.title"))
        self.root.geometry("1000x720"); self.root.minsize(900, 600)
        self.root.columnconfigure(0, weight=0); self.root.columnconfigure(1, weight=1); self.root.rowconfigure(0, weight=1)

        sidebar = ttk.Frame(self.root, padding=(8,8))
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False); sidebar.configure(width=320)

        self.lbl_conversations = ttk.Label(sidebar, text=self.tr("sidebar.conversations"), font=("Helvetica", 12, "bold"))
        self.lbl_conversations.grid(row=0, column=0, sticky="w")

        tools = ttk.Frame(sidebar); tools.grid(row=1, column=0, pady=(6,8), sticky="ew")
        self.btn_new = ttk.Button(tools, text=self.tr("btn.new"), command=self._new_chat); self.btn_new.pack(side="left")
        self.btn_contacts = ttk.Button(tools, text=self.tr("btn.contacts"), command=self._open_contacts_manager); self.btn_contacts.pack(side="left", padx=6)
        self.btn_identities = ttk.Button(tools, text=self.tr("btn.identities"), command=self._open_identities_manager); self.btn_identities.pack(side="left")

        self.conv_list = tk.Listbox(sidebar, height=26, activestyle="dotbox")
        self.conv_list.grid(row=2, column=0, sticky="nsew"); sidebar.rowconfigure(2, weight=1)
        self.conv_list.bind("<<ListboxSelect>>", self._on_select_conversation)

        self.status_lbl = ttk.Label(sidebar, text=self.tr("status.offline"), foreground="gray")
        self.status_lbl.grid(row=3, column=0, sticky="w", pady=(8,2))
        self.secure_var = tk.BooleanVar(value=self.cfg.get("secure_mode", False))
        self.chk_secure = ttk.Checkbutton(sidebar, text=self.tr("checkbox.secure"), variable=self.secure_var, command=self._toggle_secure)
        self.chk_secure.grid(row=4, column=0, sticky="w")

        main = ttk.Frame(self.root, padding=(8,8)); main.grid(row=0, column=1, sticky="nsew")
        main.rowconfigure(1, weight=1); main.columnconfigure(0, weight=1)

        header_line = ttk.Frame(main); header_line.grid(row=0, column=0, columnspan=2, sticky="ew")
        header_line.columnconfigure(0, weight=1)
        self.header_lbl = ttk.Label(header_line, text=self.tr("header.none"), font=("Helvetica", 12, "bold"))
        self.header_lbl.grid(row=0, column=0, sticky="w")
        self.btn_add_from_msg = ttk.Button(header_line, text=self.tr("btn.add_contact_from_msg"), command=self._add_contact_from_current)
        self.btn_add_from_msg.grid(row=0, column=1, sticky="e"); self.btn_add_from_msg.grid_remove()

        self.chat_text = tk.Text(main, wrap="word", state="disabled", spacing1=4, spacing3=4, padx=8, pady=8)
        self.chat_text.grid(row=1, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(main, orient="vertical", command=self.chat_text.yview)
        yscroll.grid(row=1, column=1, sticky="ns")
        self.chat_text.configure(yscrollcommand=yscroll.set)

        self.chat_text.tag_configure("in",  justify="left",  lmargin1=6, lmargin2=6, rmargin=60)
        self.chat_text.tag_configure("out", justify="right", lmargin1=60, lmargin2=60, rmargin=6)
        self.chat_text.tag_configure("meta_in",  foreground="#666", font=("Helvetica", 9, "italic"), justify="left",  lmargin1=6,  lmargin2=6,  rmargin=60)
        self.chat_text.tag_configure("meta_out", foreground="#666", font=("Helvetica", 9, "italic"), justify="right", lmargin1=60, lmargin2=60, rmargin=6)
        self.chat_text.tag_configure("filelink", underline=1)

        input_row = ttk.Frame(main); input_row.grid(row=2, column=0, sticky="ew", pady=(8,0))
        input_row.columnconfigure(1, weight=1)
        self.attach_btn = ttk.Button(input_row, text="📎", width=3, command=self._send_file_dialog)
        self.attach_btn.grid(row=0, column=0, padx=(0,6))
        self.entry = ttk.Entry(input_row); self.entry.grid(row=0, column=1, sticky="ew")
        self.entry.bind("<Control-Return>", lambda e: self._send_text())
        self.entry.bind("<Command-Return>", lambda e: self._send_text())
        self.send_btn = ttk.Button(input_row, text=("Envoyer" if self.i18n.current_lang()=="fr" else "Send"), command=self._send_text)
        self.send_btn.grid(row=0, column=2, padx=(6,0))

        self._build_menu()

        try:
            style = ttk.Style()
            if "clam" in style.theme_names(): style.theme_use("clam")
        except Exception:
            pass

    def _build_menu(self):
        menubar = tk.Menu(self.root)

        lang_menu = tk.Menu(menubar, tearoff=0)
        self.lang_var = tk.StringVar(value=self.i18n.current_lang())
        lang_menu.add_radiobutton(label=self.tr("lang.fr"), value="fr", variable=self.lang_var, command=lambda: self._change_language("fr"))
        lang_menu.add_radiobutton(label=self.tr("lang.en"), value="en", variable=self.lang_var, command=lambda: self._change_language("en"))
        menubar.add_cascade(label=self.tr("menu.lang"), menu=lang_menu)

        actions = tk.Menu(menubar, tearoff=0)
        actions.add_command(label=self.tr("menu.actions.refresh"), command=self._manual_refresh)
        actions.add_command(label=self.tr("menu.actions.settings"), command=self._open_settings)
        menubar.add_cascade(label=self.tr("menu.actions"), menu=actions)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label=self.tr("menu.help.source"), command=lambda: webbrowser.open(REPO_URL))
        help_menu.add_command(label=self.tr("menu.help.license"), command=lambda: webbrowser.open(LICENSE_URL))
        help_menu.add_separator()
        help_menu.add_command(
            label=self.tr("menu.help.about"),
            command=lambda: messagebox.showinfo(self.tr("about.title"), self.tr("about.text", url=REPO_URL))
        )
        menubar.add_cascade(label=self.tr("menu.help"), menu=help_menu)

        self.root.config(menu=menubar)

    def _open_settings(self):
        dlg = SettingsDialog(self.root, self.tr, self.cfg)
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        self.cfg.update(dlg.result)
        save_config(self.cfg)
        # Rebuild network stack
        self.http.update(use_tor=self.cfg.get("use_tor", True), socks_proxy_url=self.cfg.get("socks_proxy"))
        self.pow = PoWHelper(self.cfg["server_url"], self.http)
        # Invalidate tokens (server URL may have changed)
        self._session_tokens.clear()

    def _change_language(self, code: str):
        self.i18n.load(code)
        self.cfg["language"] = code
        save_config(self.cfg)
        self._apply_language()

    def _apply_language(self):
        self.root.title(self.tr("app.title"))
        self.lbl_conversations.config(text=self.tr("sidebar.conversations"))
        self.btn_new.config(text=self.tr("btn.new"))
        self.btn_contacts.config(text=self.tr("btn.contacts"))
        self.btn_identities.config(text=self.tr("btn.identities"))
        self.chk_secure.config(text=self.tr("checkbox.secure"))
        if not self.current_conv:
            self.header_lbl.config(text=self.tr("header.none"))
        self.btn_add_from_msg.config(text=self.tr("btn.add_contact_from_msg"))
        self.send_btn.config(text=("Envoyer" if self.i18n.current_lang()=="fr" else "Send"))
        self._build_menu()
        try:
            current = self.status_lbl.cget("text")
            online = "en ligne" in current or "online" in current
            self._set_status(online)
        except Exception:
            pass
        self._refresh_conv_sidebar()

    # ----- managers -----
    def _open_identities_manager(self):
        def after_add_or_change(idn):
            try:
                url = self.cfg["server_url"].rstrip("/") + "/register"
                signed_post(self.http, url, {"box_pub": idn.box_pub_hex}, idn.sign_sk, idn.sign_pub_hex)
            except Exception as e:
                print("Register failed:", e)
        IdentitiesManager(self.root, self.ident_store, self.tr,
                          on_added=after_add_or_change,
                          on_changed=after_add_or_change)

    def _open_contacts_manager(self):
        def after_id_added(idn):
            try:
                url = self.cfg["server_url"].rstrip("/") + "/register"
                signed_post(self.http, url, {"box_pub": idn.box_pub_hex}, idn.sign_sk, idn.sign_pub_hex)
            except Exception as e:
                print("Register failed:", e)
        ContactsManager(self.root, self.contacts, self.ident_store, self.tr,
                        on_identity_added=after_id_added)

    # ----- conversations -----
    def _refresh_conv_sidebar(self, select_key: Optional[Tuple[str,str]] = None):
        prev_key = self._current_key
        if select_key is None:
            select_key = prev_key

        self.conv_list.delete(0, tk.END)
        self._index_to_key.clear()

        items = sorted(self.conversations.items(), key=lambda kv: kv[1].contact_name.lower())
        for key, conv in items:
            badge = f" •{conv.unread}" if conv.unread else ""
            label = f"{conv.contact_name} (via {conv.identity_name}) · {conv.contact_pub_hex[:6]}…{conv.contact_pub_hex[-6:]}{badge}"
            self.conv_list.insert(tk.END, label)
            self._index_to_key.append(key)

        if select_key and select_key in self._index_to_key:
            idx = self._index_to_key.index(select_key)
            self.conv_list.selection_clear(0, tk.END)
            self.conv_list.selection_set(idx)
            self.conv_list.see(idx)
            self._current_key = select_key
            self.current_conv = self.conversations.get(select_key)
        elif self._index_to_key:
            self.conv_list.selection_set(0)
            self._current_key = self._index_to_key[0]
            self.current_conv = self.conversations[self._current_key]
        else:
            self._current_key = None
            self.current_conv = None
        self._render_header(); self._render_conversation()

    def _new_chat(self):
        items = self.contacts.items()
        if not items:
            messagebox.showinfo(self.tr("contacts.title"), self.tr("info.add_contact_first"))
            self._open_contacts_manager(); return
        dlg = SelectContactDialog(self.root, self.contacts, self.ident_store, self.tr)
        self.root.wait_window(dlg)
        if not dlg.result: return
        self._open_conversation(dlg.result)

    def _open_conversation(self, c: Dict):
        idn = self.ident_store.identities.get(c["identity_id"])
        key = (idn.id, c["pub_hex"])
        if key not in self.conversations:
            self.conversations[key] = Conversation(idn.id, idn.name, c["name"], c["pub_hex"])
        self._current_key = key
        self.current_conv = self.conversations[key]
        self._refresh_conv_sidebar(select_key=key)
        self._save_history()

    def _on_select_conversation(self, _evt):
        idxs = self.conv_list.curselection()
        if not idxs: return
        key = self._index_to_key[idxs[0]]
        self._current_key = key
        self.current_conv = self.conversations[key]
        self.current_conv.unread = 0
        self._refresh_conv_sidebar(select_key=key)
        self._save_history()

    # ----- UI helpers -----
    def _update_add_contact_button(self):
        if not self.current_conv:
            self.btn_add_from_msg.grid_remove(); return
        if self.contacts.find_by_pub(self.current_conv.contact_pub_hex):
            self.btn_add_from_msg.grid_remove()
        else:
            self.btn_add_from_msg.grid()

    def _render_header(self):
        if not self.current_conv:
            self.header_lbl.config(text=self.tr("header.none"))
            self._update_add_contact_button(); return
        c = self.current_conv
        self.header_lbl.config(text=f"{c.contact_name}  (via {c.identity_name})")
        self._update_add_contact_button()

    def _append_line(self, txt, tag):
        self.chat_text.configure(state="normal")
        self.chat_text.insert("end", txt + "\n", (tag,))
        self.chat_text.configure(state="disabled"); self.chat_text.see("end")

    def _append_image(self, data_bytes, tag):
        """Render image safely using defensive opener."""
        pil_img = self._safe_open_thumbnail(data_bytes)
        if pil_img is None:
            self._append_line("[image]", tag)
            return
        self.chat_text.configure(state="normal")
        img = ImageTk.PhotoImage(pil_img)
        self.current_conv._image_refs.append(img)  # prevent GC
        self.chat_text.image_create("end", image=img, padx=8)
        self.chat_text.insert("end", "\n", (tag,))
        self.chat_text.configure(state="disabled")
        self.chat_text.see("end")

    def _append_file_link(self, filename, data_bytes, tag):
        self.chat_text.configure(state="normal")
        link_text = self.tr("file.save", filename=filename)
        tagname = f"filelink_{len(getattr(self.current_conv,'_image_refs',[]))}_{time.time()}"
        self.chat_text.insert("end", link_text + "\n", (tag, tagname))
        def save_file(_evt, payload=data_bytes, fname=filename):
            path = filedialog.asksaveasfilename(initialfile=fname)
            if not path: return
            try:
                with open(path, "wb") as f: f.write(payload)
                messagebox.showinfo("OK", self.tr("file.saved_to", path=path))
            except Exception as e:
                messagebox.showerror("Error", str(e))
        self.chat_text.tag_bind(tagname, "<Button-1>", save_file)
        self.chat_text.configure(state="disabled"); self.chat_text.see("end")

    def _render_conversation(self):
        if not self._history_loaded and (not self.current_conv or not self.current_conv.messages):
            try:
                self.chat_text.configure(state="normal")
                self.chat_text.insert("end", self.tr("loading.history") + "\n", ("meta_in",))
                self.chat_text.configure(state="disabled")
            except Exception:
                pass
            return

        self.chat_text.configure(state="normal"); self.chat_text.delete("1.0", "end"); self.chat_text.configure(state="disabled")
        if not self.current_conv: return
        for m in self.current_conv.messages:
            direction = "out" if m["direction"] == "out" else "in"
            meta_tag = "meta_out" if direction == "out" else "meta_in"
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m["ts"]))
            if m["kind"] == "text":
                self._append_line(m["text"], direction)
            else:
                # Lazy decode des payloads binaires
                if "data" not in m and "data_b64" in m:
                    try:
                        m["data"] = base64.b64decode(m["data_b64"])
                    except Exception:
                        m["data"] = b""

                if m["kind"] == "image":
                    self._append_image(m.get("data", b""), direction)
                else:
                    self._append_file_link(m.get("filename","file"), m.get("data", b""), direction)

            if m.get("pending"):
                txt = self.tr("msg.sending")
                if "progress" in m:
                    try: txt += f" {int(m['progress'])}%"
                    except: pass
                self._append_line(txt, meta_tag)

                if "local_id" in m:
                    tagname = f"cancel_{m['local_id']}"
                    self.chat_text.configure(state="normal")
                    self.chat_text.insert("end", "[" + self.tr("msg.cancel") + "]\n", (meta_tag, tagname))
                    self.chat_text.tag_bind(tagname, "<Button-1>", lambda _e, mid=m["local_id"]: self._cancel_message(mid))
                    self.chat_text.configure(state="disabled")
            elif m.get("status") == "sent":
                self._append_line(self.tr("msg.sent"), meta_tag)
            elif m.get("status") == "failed":
                self._append_line(self.tr("msg.failed"), meta_tag)

            self._append_line(ts, meta_tag)

    # ===== async send =====
    def _inc_busy(self):
        if self._busy == 0:
            try:
                self.send_btn.config(state="disabled")
                self.attach_btn.config(state="disabled")
            except: pass
        self._busy += 1

    def _dec_busy(self):
        self._busy = max(self._busy - 1, 0)
        if self._busy == 0:
            try:
                self.send_btn.config(state="normal")
                self.attach_btn.config(state="normal")
            except: pass

    def _cancel_message(self, local_id: str):
        ev = self._pending.get(local_id)
        if ev: ev.set()
        if self.current_conv:
            before = len(self.current_conv.messages)
            self.current_conv.messages = [m for m in self.current_conv.messages if m.get("local_id") != local_id]
            if len(self.current_conv.messages) != before:
                self._render_conversation(); self._save_history()

    def _send_payload_async(self, recipient_pub_hex: str, payload_builder_callable, on_done=None, progress_setter=None):
        cancel_event = threading.Event()
        local_id = str(uuid.uuid4())
        self._pending[local_id] = cancel_event

        def ui_progress(p):
            if progress_setter:
                try:
                    self.root.after(0, lambda: (progress_setter(max(0, min(100, p))), self._render_conversation()))
                except:
                    pass

        def worker():
            ok = True
            cancelled = False
            try:
                # 0..10% prepare
                ui_progress(1)
                if cancel_event.is_set():
                    raise RuntimeError("CANCELLED")
                payload = payload_builder_callable(lambda p: ui_progress(min(p, 10)))

                # 10..20% encrypt
                ui_progress(12)
                if cancel_event.is_set():
                    raise RuntimeError("CANCELLED")
                cipher_hex = encrypt_for(recipient_pub_hex, payload)
                ui_progress(20)

                # 20..90% PoW
                def pow_hook(tries, expected):
                    if cancel_event.is_set():
                        raise RuntimeError("CANCELLED")
                    try:
                        frac = float(tries) / float(expected)
                    except Exception:
                        frac = 0.0
                    ui_progress(20 + 70 * min(0.999, max(0.0, frac)))

                nonce_hex = self.pow.compute_nonce(cipher_hex, progress_hook=pow_hook, cancel_event=cancel_event)
                ui_progress(90)
                if cancel_event.is_set():
                    raise RuntimeError("CANCELLED")

                # 90..100% HTTP upload
                url = self.cfg["server_url"].rstrip("/") + "/put/"
                exp = int(time.time()) + 24 * 3600
                body = {
                    "recipient": recipient_pub_hex,
                    "expiration_time": exp,
                    "cipher_hex": cipher_hex,
                    "pow": {"salt": self.pow.salt, "nonce": nonce_hex}
                }
                body_bytes = json.dumps(body, separators=(',', ':')).encode()

                class ProgressBytesIO(io.BytesIO):
                    def __init__(self, buf):
                        super().__init__(buf)
                        self._total = len(buf)
                        self._sent = 0
                    def read(self, n=-1):
                        if cancel_event.is_set():
                            raise RuntimeError("CANCELLED")
                        chunk = super().read(n)
                        self._sent += len(chunk)
                        if self._total > 0:
                            frac = self._sent / self._total
                            ui_progress(90 + 10 * min(1.0, max(0.0, frac)))
                        return chunk

                headers = {"Content-Type": "application/json"}
                stream = ProgressBytesIO(body_bytes)
                self.http.post(url, data=stream, headers=headers, timeout=20).raise_for_status()
                ui_progress(100)

            except Exception as e:
                ok = False
                cancelled = (str(e) == "CANCELLED")
                if not cancelled:
                    self.root.after(0, lambda msg=str(e): messagebox.showerror("Error", msg))
            finally:
                try:
                    del self._pending[local_id]
                except:
                    pass
                if on_done:
                    self.root.after(0, lambda: on_done(ok, cancelled))
                self.root.after(0, self._dec_busy)
                self.root.after(0, self._save_history)

        self._inc_busy()
        threading.Thread(target=worker, daemon=True).start()
        return local_id

    # ----- send text -----
    def _send_text(self):
        c = self.current_conv
        if not c:
            messagebox.showwarning("Info", self.tr("error.no_active_conversation")); return
        msg = self.entry.get().strip()
        if not msg: return
        self.entry.delete(0, tk.END)
        idn = self.ident_store.identities[c.identity_id]
        ts = int(time.time())

        item = {"local_id": "", "direction":"out","kind":"text","text":msg,"ts":ts,"pending":True,"progress":0}
        c.messages.append(item); self._render_conversation(); self._save_history()

        def set_prog(p): item["progress"] = p

        def build(progress_cb):
            progress_cb(3)
            payload = {
                "t": "text",
                "sender_box_pub": idn.box_pub_hex,
                "sender_sign_pub": idn.sign_pub_hex,
                "text": msg,
                "ts": ts
            }
            to_sign = canonical_dumps({k:v for k,v in payload.items() if k!="sig"})
            payload["sig"] = idn.sign_sk.sign(to_sign).signature.hex()
            progress_cb(8); return payload

        def done(ok, cancelled):
            if cancelled: return
            item["pending"] = False
            item["status"] = "sent" if ok else "failed"
            item.pop("progress", None)
            self._render_conversation()

        local_id = self._send_payload_async(c.contact_pub_hex, build, on_done=done, progress_setter=set_prog)
        item["local_id"] = local_id; self._render_conversation()

    # ----- send file/image -----
    def _send_file_dialog(self):
        """Allow file selection; if image, show EXIF dialog and allow stripping before send."""
        c = self.current_conv
        if not c:
            messagebox.showwarning("Info", self.tr("error.no_active_conversation"))
            return
        path = filedialog.askopenfilename()
        if not path:
            return

        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        filename = os.path.basename(path)
        mime, _ = mimetypes.guess_type(path)
        is_image = bool(mime and mime.startswith("image/"))

        # Optional EXIF review & stripping for images
        if is_image:
            try:
                img = Image.open(io.BytesIO(data))
                exif_text = self._exif_to_text(img)
                from interface import ExifDialog
                dlg = ExifDialog(self.root, self.tr, exif_text)
                self.root.wait_window(dlg)
                if dlg.result is None:
                    return  # user canceled
                if dlg.result.get("remove"):
                    data = self._strip_exif_bytes(data, mime)
            except Exception:
                # If we fail to parse EXIF, fall through and send as-is
                pass

        idn = self.ident_store.identities[c.identity_id]
        ts = int(time.time())

        item = {
            "local_id": "",
            "direction": "out",
            "kind": "image" if is_image else "file",
            "data": data,
            "filename": filename,
            "ts": ts,
            "pending": True,
            "progress": 0
        }
        c.messages.append(item)
        self._render_conversation()
        self._save_history()

        def set_prog(p):
            item["progress"] = p

        def b64encode_with_progress(buf: bytes, progress_cb, start=0.0, end=10.0):
            """Chunked base64 to keep UI progress meaningful on large files."""
            if not buf:
                progress_cb(end)
                return ""
            chunk = 64 * 1024
            total = len(buf)
            out_parts = []
            done = 0
            carry = b""
            for i in range(0, total, chunk):
                block = carry + buf[i:i + chunk]
                rem = len(block) % 3
                to_enc = block if rem == 0 else block[:-rem]
                if to_enc:
                    out_parts.append(base64.b64encode(to_enc))
                carry = b"" if rem == 0 else block[-rem:]
                done += min(chunk, total - i)
                progress_cb(start + (end - start) * (done / total))
            if carry:
                out_parts.append(base64.b64encode(carry))
            return b"".join(out_parts).decode("ascii")

        def build(progress_cb):
            b64 = b64encode_with_progress(data, progress_cb, 0, 10)
            payload = {
                "t": "image" if is_image else "file",
                "sender_box_pub": idn.box_pub_hex,
                "sender_sign_pub": idn.sign_pub_hex,
                "filename": filename,
                "mime": mime,
                "data_b64": b64,
                "ts": ts
            }
            to_sign = canonical_dumps({k: v for k, v in payload.items() if k != "sig"})
            payload["sig"] = idn.sign_sk.sign(to_sign).signature.hex()
            progress_cb(10)
            return payload

        def done(ok, cancelled):
            if cancelled:
                return
            item["pending"] = False
            item["status"] = "sent" if ok else "failed"
            item.pop("progress", None)
            self._render_conversation()

        local_id = self._send_payload_async(c.contact_pub_hex, build, on_done=done, progress_setter=set_prog)
        item["local_id"] = local_id
        self._render_conversation()

    # ----- add contact from current -----
    def _add_contact_from_current(self):
        """Create a contact from the current unknown conversation and pin the observed signing key."""
        if not self.current_conv:
            return
        conv = self.current_conv
        if self.contacts.find_by_pub(conv.contact_pub_hex):
            self._update_add_contact_button()
            return
        idents = self.ident_store.list()
        ident_default = conv.identity_id  # identity that received the message

        # No new identity allowed here; lock to the receiving identity
        dlg = ContactDialog(
            self.root, idents, self.tr,
            "contact.title.new",
            name="",
            key=conv.contact_pub_hex,
            sign_key=(conv._last_sender_sign_pub or ""),
            identity_id=ident_default,
            allow_new_identity=False,
            fixed_identity_id=ident_default
        )
        self.root.wait_window(dlg)
        if dlg.result:
            name, key, sign, ident_id, _extra = dlg.result
            self.contacts.add(name, key, sign, ident_id)
            conv.contact_name = name
            self._refresh_conv_sidebar(select_key=(conv.identity_id, conv.contact_pub_hex))
            self._save_history()

    # ----- actions -----
    def _manual_refresh(self):
        def worker():
            ok = True
            try:
                for idn in self.ident_store.list():
                    self._poll_once_for_identity(idn)
            except Exception:
                ok = False
            self.root.after(0, lambda: self._set_status(ok))
        threading.Thread(target=worker, daemon=True).start()

    # ----- polling -----
    def _start_poll_thread(self):
        threading.Thread(target=self._poll_loop, daemon=True).start()

    def _poll_loop(self):
        while True:
            ok = True
            try:
                for idn in self.ident_store.list():
                    self._poll_once_for_identity(idn)
            except Exception:
                ok = False

            try:
                self.root.after(0, lambda ok=ok: self._set_status(ok))
            except Exception:
                pass

            base = float(self.cfg.get("polling_base", 5.0))
            jitter = float(self.cfg.get("polling_jitter", 3.0))
            sleep_s = max(0.5, base + random.uniform(-jitter, jitter))
            time.sleep(sleep_s)

    def _set_status(self, online: bool):
        txt = self.tr("status.online") if online else self.tr("status.offline")
        color = "green" if online else "red"
        try: self.status_lbl.config(text=txt, foreground=color)
        except: pass

    # ----- session tokens (ephemeral) -----
    def _ensure_session_token(self, idn) -> Optional[str]:
        now = int(time.time())
        tok = self._session_tokens.get(idn.id)
        if tok and tok[1] - 5 > now:
            return tok[0]
        # fetch new token (signed)
        try:
            url = self.cfg["server_url"].rstrip("/") + "/session_token"
            r = signed_post(self.http, url, {}, idn.sign_sk, idn.sign_pub_hex)
            r.raise_for_status()
            data = r.json()
            token = data.get("token"); exp = int(data.get("expires_at", now+300))
            if token:
                self._session_tokens[idn.id] = (token, exp)
                return token
        except Exception as e:
            print("session_token error:", e)
        return None

    def _poll_once_for_identity(self, idn):
        """Fetch encrypted messages, verify signatures, enforce pinning and anti-replay."""
        token = self._ensure_session_token(idn)
        if not token:
            raise RuntimeError("No session token")
        url = self.cfg["server_url"].rstrip("/") + "/get/"
        headers = {"X-Session-Token": token, "Content-Type": "application/json"}
        r = self.http.post(url, data=b"{}", headers=headers, timeout=20)
        if r.status_code != 200:
            raise RuntimeError("Server unavailable")
        data = r.json()
        updated = False

        for msg in data.get("messages", []):
            mid = msg["id"]
            if mid in self._seen_ids:
                continue
            self._seen_ids.add(mid)

            cipher_hex = msg["cipher_hex"]
            try:
                pt_bytes = decrypt_with(idn.box_sk, cipher_hex)
                payload = json.loads(pt_bytes.decode())
            except Exception:
                continue

            # Verify sender's detached signature over canonical payload
            sig_hex = payload.get("sig", "")
            to_verify = {k: v for k, v in payload.items() if k != "sig"}
            body_bytes = canonical_dumps(to_verify)
            sender_sign_pub = payload.get("sender_sign_pub", "")
            try:
                _VerifyKey(bytes.fromhex(sender_sign_pub)).verify(body_bytes, bytes.fromhex(sig_hex))
            except Exception:
                continue

            # Anti-replay: hash the signed payload and enforce time window
            from security import sha256_hex
            payload_hash = sha256_hex(body_bytes)
            signed_ts = int(payload.get("ts") or time.time())
            now = int(time.time())
            if abs(now - signed_ts) > 48 * 3600:
                # Too old or too far in the future; drop
                continue

            sender_box_pub = payload.get("sender_box_pub", "")
            key = (idn.id, sender_box_pub)
            if key not in self.conversations:
                self.conversations[key] = Conversation(
                    idn.id, idn.name,
                    self.tr("unknown.contact", prefix=sender_box_pub[:6]),
                    sender_box_pub
                )
            conv = self.conversations[key]
            if payload_hash in conv.replay_recent:
                # Duplicate payload (replay); drop
                continue
            conv.replay_recent.append(payload_hash)

            # Resolve contact and enforce signing-key pinning (key continuity)
            contact = self.contacts.find_by_pub(sender_box_pub)
            contact_name = contact["name"] if contact else self.tr("unknown.contact", prefix=sender_box_pub[:6])
            conv.contact_name = contact_name  # keep label in sync

            if contact and contact.get("sign_pub_hex"):
                pinned = contact["sign_pub_hex"]
                if pinned != sender_sign_pub:
                    # Signing key changed: ask user whether to trust the new one.
                    def _ask_key_change():
                        if messagebox.askyesno(
                            self.tr("keychange.title"),
                            self.tr("keychange.text",
                                    name=contact_name,
                                    old=pinned[:10] + "…" + pinned[-8:],
                                    new=sender_sign_pub[:10] + "…" + sender_sign_pub[-8:])
                        ):
                            # Update pinned signing key
                            items = self.contacts.items()
                            idx = next((i for i, cx in enumerate(items) if cx["pub_hex"] == sender_box_pub), None)
                            if idx is not None:
                                self.contacts.update(idx, contact["name"], contact["pub_hex"], sender_sign_pub, contact["identity_id"])
                        # Either way, do not deliver this message until user decides.
                    try:
                        self.root.after(0, _ask_key_change)
                    except Exception:
                        pass
                    continue  # hold message until decision
            else:
                # Unknown sender: remember the observed signing key to pre-fill the add-contact flow
                conv._last_sender_sign_pub = sender_sign_pub

            # Decode and append message content
            kind = payload.get("t")
            try:
                if kind == "text":
                    text = payload.get("text", "")
                    conv.messages.append({"direction": "in", "kind": "text", "text": text, "ts": signed_ts})
                elif kind == "image":
                    raw = base64.b64decode(payload.get("data_b64", ""), validate=True)
                    conv.messages.append({"direction": "in", "kind": "image", "data": raw, "filename": payload.get("filename"), "ts": signed_ts})
                else:
                    raw = base64.b64decode(payload.get("data_b64", ""), validate=True)
                    conv.messages.append({"direction": "in", "kind": "file", "data": raw, "filename": payload.get("filename"), "ts": signed_ts})
            except binascii.Error:
                continue

            if self.current_conv is None or conv is not self.current_conv:
                conv.unread += 1
            updated = True

        if updated:
            try:
                self.root.after(0, lambda: (self._refresh_conv_sidebar(select_key=self._current_key), self._save_history()))
            except Exception:
                pass

    def _toggle_secure(self):
        new_val = bool(self.secure_var.get())
        self.cfg["secure_mode"] = new_val
        save_config(self.cfg)
        if new_val:
            if messagebox.askyesno(self.tr("secure.confirm.title"), self.tr("secure.confirm.text")):
                for p in (IDENTS_FILE, CONTACTS_FILE, VAULT_FILE, VAULT_KEY_FILE):
                    try:
                        if os.path.exists(p): os.remove(p)
                    except: pass
                self._seen_ids.clear(); self.conversations.clear()
                self._current_key = None
                self.ident_store = IdentityStore(bootstrap_default=False)
                self.contacts = ContactsStore()
                self._refresh_conv_sidebar()
            else:
                self.secure_var.set(False)
                self.cfg["secure_mode"] = False; save_config(self.cfg)
        else:
            self._save_history()

    def _on_close(self):
        if self.cfg.get("secure_mode", False):
            if not messagebox.askyesno(self.tr("secure.exit.title"), self.tr("secure.exit.text")):
                return
            for p in (IDENTS_FILE, CONTACTS_FILE, VAULT_FILE, VAULT_KEY_FILE):
                try:
                    if os.path.exists(p): os.remove(p)
                except: pass
        else:
            self._save_history()
        self.root.destroy()

    def _exif_to_text(self, pil_img) -> str:
        """Extract a readable JSON string of EXIF-like metadata for user review."""
        try:
            meta = {}
            if hasattr(pil_img, "getexif"):
                exif = pil_img.getexif()
                if exif:
                    for k, v in exif.items():
                        tag = ExifTags.TAGS.get(k, str(k))
                        meta[tag] = str(v)
            # Some formats store extra metadata in .info
            if getattr(pil_img, "info", None):
                for k in ("exif", "icc_profile", "XML:com.adobe.xmp"):
                    if k in pil_img.info:
                        meta[k] = f"{len(pil_img.info[k])} bytes"
            import json as _json
            return _json.dumps(meta or {}, indent=2, ensure_ascii=False)
        except Exception:
            return "{}"

    def _strip_exif_bytes(self, data: bytes, mime: Optional[str]) -> bytes:
        """Re-encode image to remove EXIF and similar metadata."""
        try:
            bio = io.BytesIO(data)
            img = Image.open(bio)
            fmt = (img.format or "").upper()
            out = io.BytesIO()
            if fmt in ("JPEG", "JPG"):
                img = img.convert("RGB")
                # Save JPEG without EXIF
                img.save(out, format="JPEG", quality=92, optimize=True, exif=b"")
            elif fmt == "PNG":
                # Re-saving PNG drops ancillary chunks by default with Pillow
                img.save(out, format="PNG")
            else:
                # Fallback: neutral PNG without metadata
                img.save(out, format="PNG")
            return out.getvalue()
        except Exception:
            # If strip fails, return original bytes to avoid silent data loss
            return data
    
    def _safe_open_thumbnail(self, data_bytes: bytes, max_w=420, max_h=320) -> Optional[Image.Image]:
        """
        Open image defensively:
        - verify() detects truncated/forged images
        - enforce global pixel cap (set at import)
        - resize to a reasonable UI size
        """
        try:
            bio = io.BytesIO(data_bytes)
            img = Image.open(bio)
            img.verify()  # basic structural validation
            # Re-open after verify (Pillow requirement)
            bio2 = io.BytesIO(data_bytes)
            img2 = Image.open(bio2)
            img2.load()
            scale = min(max_w / img2.width, max_h / img2.height, 1.0)
            if scale < 1.0:
                img2 = img2.resize((int(img2.width * scale), int(img2.height * scale)), Image.LANCZOS)
            return img2
        except Exception:
            return None

# ===== main =====
if __name__ == "__main__":
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names(): style.theme_use("clam")
    except Exception:
        pass
    app = MessengerApp(root)
    root.mainloop()
