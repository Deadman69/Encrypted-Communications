import sys, os, json, time, threading, random, mimetypes, base64, io, uuid, webbrowser, hashlib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from typing import Optional, List, Dict, Tuple
from PIL import Image, ImageTk, ImageFile

ImageFile.LOAD_TRUNCATED_IMAGES = True

from nacl.public import PrivateKey, PublicKey
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
from nacl.signing import VerifyKey as _VerifyKey
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random

import requests

from security import canonical_dumps, signed_post, encrypt_for, decrypt_with, PoWHelper
from interface import (
    I18n, ContactDialog, IdentityDialog, IdentitiesManager, ContactsManager,
    SelectContactDialog
)

# =============== Fichiers & config ===============
CONFIG_FILE = "config.json"
IDENTS_FILE = "identities.json"
CONTACTS_FILE = "contacts.json"
VAULT_FILE = "conversations.vault"
VAULT_KEY_FILE = "vault.key"

REPO_URL = "https://github.com/Deadman69/Encrypted-Communications"
LICENSE_URL = "https://www.gnu.org/licenses/agpl-3.0.en.html"

DEFAULT_CONFIG = {
    "server_url": "http://localhost:8000",
    "polling_interval": 5,
    "language": "en",
    "secure_mode": False
}

def bundle_path(*parts):
    base = getattr(sys, "_MEIPASS", os.path.dirname(__file__))
    return os.path.join(base, *parts)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE,"r", encoding="utf-8") as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    with open(CONFIG_FILE,"w", encoding="utf-8") as f:
        json.dump(DEFAULT_CONFIG,f,indent=4, ensure_ascii=False)
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    with open(CONFIG_FILE,"w", encoding="utf-8") as f:
        json.dump(cfg,f,indent=4, ensure_ascii=False)

# =============== Modèles ===============
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
    def __init__(self, path=IDENTS_FILE, bootstrap_default: bool = True):
        self.path = path
        self.bootstrap_default = bootstrap_default
        self.identities: Dict[str, Identity] = {}
        self.load()

    def load(self):
        if os.path.exists(self.path):
            with open(self.path,"r", encoding="utf-8") as f:
                arr = json.load(f)
        else:
            if self.bootstrap_default:
                arr = [Identity.generate("Default Identity").to_dict()]
            else:
                arr = []
            with open(self.path,"w", encoding="utf-8") as f:
                json.dump(arr,f,indent=4, ensure_ascii=False)
        self.identities = {d["id"]: Identity(
            id_=d["id"], name=d["name"],
            box_sk_hex=d["box_private_key"], box_pk_hex=d["box_public_key"],
            sign_sk_hex=d["sign_private_key"], sign_pk_hex=d["sign_public_key"]
        ) for d in arr}

    def save(self):
        arr = [idn.to_dict() for idn in self.identities.values()]
        with open(self.path,"w", encoding="utf-8") as f:
            json.dump(arr,f,indent=4, ensure_ascii=False)

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

    def replace_keys(self, id_: str, *,
                     box_sk_hex: str, box_pk_hex: str,
                     sign_sk_hex: str, sign_pk_hex: str):
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
    def __init__(self, path=CONTACTS_FILE):
        self.path = path
        self._arr: List[Dict] = []
        self.load()

    def load(self):
        if os.path.exists(self.path):
            with open(self.path,"r", encoding="utf-8") as f:
                self._arr = json.load(f)
        else:
            self._arr = []; self.save()

    def save(self):
        with open(self.path,"w", encoding="utf-8") as f:
            json.dump(self._arr,f,indent=4, ensure_ascii=False)

    def items(self) -> List[Dict]:
        return list(self._arr)

    def add(self, name: str, pub_hex: str, identity_id: str):
        self._arr.append({"name": name, "pub_hex": pub_hex, "identity_id": identity_id}); self.save()

    def update(self, idx: int, name: str, pub_hex: str, identity_id: str):
        self._arr[idx] = {"name": name, "pub_hex": pub_hex, "identity_id": identity_id}; self.save()

    def delete(self, idx: int):
        del self._arr[idx]; self.save()

    def find_by_pub(self, pub_hex: str) -> Optional[Dict]:
        for c in self._arr:
            if c["pub_hex"] == pub_hex: return c
        return None

class Conversation:
    def __init__(self, ident_id: str, ident_name: str, contact_name: str, contact_pub_hex: str):
        self.identity_id = ident_id
        self.identity_name = ident_name
        self.contact_name = contact_name
        self.contact_pub_hex = contact_pub_hex
        self.messages = []  # [{local_id?, direction, kind, text/filename/data, ts, pending/status, progress}]
        self._image_refs = []
        self.unread = 0

# =============== Application ===============
class MessengerApp:
    def __init__(self, root):
        self.root = root
        self.cfg = load_config()
        # i18n
        self.i18n = I18n(langs_dir=bundle_path("langs"), default_lang=self.cfg.get("language", "en"))
        self.tr = self.i18n.t

        # Secure: purge au démarrage (tout sauf config)
        if self.cfg.get("secure_mode", False):
            for p in (IDENTS_FILE, CONTACTS_FILE, VAULT_FILE, VAULT_KEY_FILE):
                try:
                    if os.path.exists(p): os.remove(p)
                except: pass

        # Stores
        self.ident_store = IdentityStore(bootstrap_default=not self.cfg.get("secure_mode", False))
        self.contacts = ContactsStore()
        self.pow = PoWHelper(self.cfg["server_url"])

        # conversations
        self.conversations: Dict[Tuple[str,str], Conversation] = {}
        self.current_conv: Optional[Conversation] = None
        self._current_key: Optional[Tuple[str,str]] = None
        self._index_to_key: List[Tuple[str,str]] = []
        self._seen_ids = set()
        self._busy = 0

        # messages en cours (annulation)
        self._pending: Dict[str, threading.Event] = {}

        # historique local chiffré (si pas secure)
        self._load_history()

        self._register_all_identities()
        self._build_ui()
        self._refresh_conv_sidebar(select_key=self._current_key)
        self._start_poll_thread()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- Vault (persistance chiffrée) ----------
    def _vault_key(self) -> bytes:
        if self.cfg.get("secure_mode", False):
            return hashlib.sha256(b"disabled").digest()
        if not os.path.exists(VAULT_KEY_FILE):
            with open(VAULT_KEY_FILE, "wb") as f:
                f.write(os.urandom(32))
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
        if self.cfg.get("secure_mode", False):
            self._purge_vault()
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
                    if "data" in m2 and isinstance(m2["data"], (bytes, bytearray)):
                        m2["data_b64"] = base64.b64encode(m2.pop("data")).decode()
                    msgs.append(m2)
                data["conversations"].append({
                    "key": list(key),
                    "identity_name": conv.identity_name,
                    "contact_name": conv.contact_name,
                    "contact_pub_hex": conv.contact_pub_hex,
                    "messages": msgs,
                    "unread": conv.unread
                })
            raw = json.dumps(data, separators=(',',':')).encode()
            box = SecretBox(self._vault_key())
            nonce = nacl_random(SecretBox.NONCE_SIZE)
            enc = box.encrypt(raw, nonce)
            with open(VAULT_FILE, "wb") as f:
                f.write(enc)
        except Exception as e:
            print("save_history error:", e)

    def _load_history(self):
        if self.cfg.get("secure_mode", False):
            self._purge_vault()
            return
        if not os.path.exists(VAULT_FILE):
            return
        try:
            with open(VAULT_FILE, "rb") as f:
                enc = f.read()
            box = SecretBox(self._vault_key())
            raw = box.decrypt(enc)
            obj = json.loads(raw.decode())
            self._current_key = tuple(obj.get("current_key") or []) or None
            for rec in obj.get("conversations", []):
                key = tuple(rec["key"])
                conv = Conversation(
                    ident_id=key[0],
                    ident_name=rec.get("identity_name",""),
                    contact_name=rec.get("contact_name",""),
                    contact_pub_hex=rec.get("contact_pub_hex", key[1])
                )
                conv.unread = int(rec.get("unread", 0))
                for m in rec.get("messages", []):
                    if "data_b64" in m:
                        m["data"] = base64.b64decode(m.pop("data_b64"))
                    conv.messages.append(m)
                self.conversations[key] = conv
        except Exception as e:
            print("load_history error:", e)

    # ----- Register -----
    def _register_identity(self, idn: Identity):
        try:
            url = self.cfg["server_url"].rstrip("/") + "/register"
            signed_post(url, {"box_pub": idn.box_pub_hex}, idn.sign_sk, idn.sign_pub_hex)
        except Exception as e:
            print("Register failed for", idn.name, e)

    def _register_all_identities(self):
        for idn in self.ident_store.list():
            self._register_identity(idn)

    # ----- UI -----
    def _build_ui(self):
        self.root.title(self.tr("app.title"))
        self.root.geometry("1000x720")
        self.root.minsize(900, 600)

        self.root.columnconfigure(0, weight=0)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

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
        self.conv_list.grid(row=2, column=0, sticky="nsew")
        sidebar.rowconfigure(2, weight=1)
        self.conv_list.bind("<<ListboxSelect>>", self._on_select_conversation)

        self.status_lbl = ttk.Label(sidebar, text=self.tr("status.offline"), foreground="gray")
        self.status_lbl.grid(row=3, column=0, sticky="w", pady=(8,2))
        self.secure_var = tk.BooleanVar(value=self.cfg.get("secure_mode", False))
        self.chk_secure = ttk.Checkbutton(sidebar, text=self.tr("checkbox.secure"), variable=self.secure_var, command=self._toggle_secure)
        self.chk_secure.grid(row=4, column=0, sticky="w")

        main = ttk.Frame(self.root, padding=(8,8))
        main.grid(row=0, column=1, sticky="nsew")
        main.rowconfigure(1, weight=1); main.columnconfigure(0, weight=1)

        # ligne d'en-tête = label + bouton "Ajouter le contact" quand inconnu
        header_line = ttk.Frame(main); header_line.grid(row=0, column=0, columnspan=2, sticky="ew")
        header_line.columnconfigure(0, weight=1)
        self.header_lbl = ttk.Label(header_line, text=self.tr("header.none"), font=("Helvetica", 12, "bold"))
        self.header_lbl.grid(row=0, column=0, sticky="w")
        self.btn_add_from_msg = ttk.Button(header_line, text=self.tr("btn.add_contact_from_msg"), command=self._add_contact_from_current)
        self.btn_add_from_msg.grid(row=0, column=1, sticky="e")
        self.btn_add_from_msg.grid_remove()  # masqué par défaut

        self.chat_text = tk.Text(main, wrap="word", state="disabled", spacing1=4, spacing3=4, padx=8, pady=8)
        self.chat_text.grid(row=1, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(main, orient="vertical", command=self.chat_text.yview)
        yscroll.grid(row=1, column=1, sticky="ns")
        self.chat_text.configure(yscrollcommand=yscroll.set)

        # Alignements
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

        # Langue
        lang_menu = tk.Menu(menubar, tearoff=0)
        self.lang_var = tk.StringVar(value=self.i18n.current_lang())
        lang_menu.add_radiobutton(label=self.tr("lang.fr"), value="fr", variable=self.lang_var, command=lambda: self._change_language("fr"))
        lang_menu.add_radiobutton(label=self.tr("lang.en"), value="en", variable=self.lang_var, command=lambda: self._change_language("en"))
        menubar.add_cascade(label=self.tr("menu.lang"), menu=lang_menu)

        # Actions
        actions = tk.Menu(menubar, tearoff=0)
        actions.add_command(label=self.tr("menu.actions.refresh"), command=self._manual_refresh)
        menubar.add_cascade(label=self.tr("menu.actions"), menu=actions)

        # Aide
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

    # ----- Managers -----
    def _open_identities_manager(self):
        def after_add_or_change(idn):
            try:
                url = self.cfg["server_url"].rstrip("/") + "/register"
                signed_post(url, {"box_pub": idn.box_pub_hex}, idn.sign_sk, idn.sign_pub_hex)
            except Exception as e:
                print("Register failed:", e)
        IdentitiesManager(self.root, self.ident_store, self.tr,
                          on_added=after_add_or_change,
                          on_changed=after_add_or_change)

    def _open_contacts_manager(self):
        ContactsManager(self.root, self.contacts, self.ident_store, self.tr)

    # ----- Conversations -----
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
            self._open_contacts_manager()
            return
        dlg = SelectContactDialog(self.root, self.contacts, self.ident_store, self.tr)
        self.root.wait_window(dlg)
        if not dlg.result:
            return
        c = dlg.result
        self._open_conversation(c)

    def _open_conversation(self, c: Dict):
        idn = self.ident_store.identities.get(c["identity_id"])
        key = (idn.id, c["pub_hex"])
        if key not in self.conversations:
            conv = Conversation(idn.id, idn.name, c["name"], c["pub_hex"])
            self.conversations[key] = conv
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
            self._update_add_contact_button()
            return
        c = self.current_conv
        self.header_lbl.config(text=f"{c.contact_name}  (via {c.identity_name})")
        self._update_add_contact_button()

    def _append_line(self, txt, tag):
        self.chat_text.configure(state="normal")
        self.chat_text.insert("end", txt + "\n", (tag,))
        self.chat_text.configure(state="disabled"); self.chat_text.see("end")

    def _append_image(self, data_bytes, tag):
        try:
            bio = io.BytesIO(data_bytes)
            pil_img = Image.open(bio)
            try:
                pil_img.load()
            except OSError:
                bio.seek(0)
                pil_img = Image.open(bio)
                pil_img.load()
        except Exception:
            self._append_line("[image]", tag)
            return

        self.chat_text.configure(state="normal")
        max_w, max_h = 420, 320
        w, h = pil_img.size
        scale = min(max_w / w, max_h / h, 1.0)
        if scale < 1.0:
            pil_img = pil_img.resize((int(w * scale), int(h * scale)), Image.LANCZOS)
        img = ImageTk.PhotoImage(pil_img)
        self.current_conv._image_refs.append(img)
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
        self.chat_text.configure(state="normal"); self.chat_text.delete("1.0", "end"); self.chat_text.configure(state="disabled")
        if not self.current_conv: return
        for m in self.current_conv.messages:
            direction = "out" if m["direction"] == "out" else "in"
            meta_tag = "meta_out" if direction == "out" else "meta_in"
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(m["ts"]))
            if m["kind"] == "text":
                self._append_line(m["text"], direction)
            elif m["kind"] == "image":
                self._append_image(m["data"], direction)
            else:
                self._append_file_link(m.get("filename","fichier"), m["data"], direction)

            if m.get("pending"):
                txt = self.tr("msg.sending")
                if "progress" in m:
                    try:
                        txt += f" {int(m['progress'])}%"
                    except:
                        pass
                self._append_line(txt, meta_tag)

                # Lien Annuler (supprime le message en cours)
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

    # ====== Envoi asynchrone ======
    def _inc_busy(self):
        if self._busy == 0:
            try:
                self.send_btn.config(state="disabled")
                self.attach_btn.config(state="disabled")
            except:
                pass
        self._busy += 1

    def _dec_busy(self):
        self._busy = max(self._busy - 1, 0)
        if self._busy == 0:
            try:
                self.send_btn.config(state="normal")
                self.attach_btn.config(state="normal")
            except:
                pass

    def _cancel_message(self, local_id: str):
        ev = self._pending.get(local_id)
        if ev:
            ev.set()
        if self.current_conv:
            before = len(self.current_conv.messages)
            self.current_conv.messages = [m for m in self.current_conv.messages if m.get("local_id") != local_id]
            if len(self.current_conv.messages) != before:
                self._render_conversation()
                self._save_history()

    def _send_payload_async(self, recipient_pub_hex: str, payload_builder_callable, on_done=None, progress_setter=None):
        """
        payload_builder_callable(progress_cb) -> dict
        progress_setter(pct: float)           -> met à jour l’UI (0..100)
        """
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
                # 0..10% : préparation (builder peut animer jusqu’à 10%)
                ui_progress(1)
                if cancel_event.is_set(): raise RuntimeError("CANCELLED")
                payload = payload_builder_callable(lambda p: ui_progress(min(p, 10)))

                # 10..20% : chiffrement
                ui_progress(12)
                if cancel_event.is_set(): raise RuntimeError("CANCELLED")
                cipher_hex = encrypt_for(recipient_pub_hex, payload)
                ui_progress(20)

                # 20..90% : PoW
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
                if cancel_event.is_set(): raise RuntimeError("CANCELLED")

                # 90..100% : upload HTTP (stream + annulation)
                url = self.cfg["server_url"].rstrip("/") + "/put/"
                exp = int(time.time()) + 24*3600
                body = {
                    "recipient": recipient_pub_hex,
                    "expiration_time": exp,
                    "cipher_hex": cipher_hex,
                    "pow": {"salt": self.pow.salt, "nonce": nonce_hex}
                }
                body_bytes = json.dumps(body, separators=(',',':')).encode()

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

                stream = ProgressBytesIO(body_bytes)
                headers = {"Content-Type": "application/json"}
                requests.post(url, data=stream, headers=headers, timeout=20).raise_for_status()
                ui_progress(100)

            except Exception as e:
                ok = False
                cancelled = (str(e) == "CANCELLED")
                if not cancelled:
                    self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
            finally:
                try: del self._pending[local_id]
                except: pass
                if on_done:
                    self.root.after(0, lambda: on_done(ok, cancelled))
                self.root.after(0, self._dec_busy)
                self.root.after(0, self._save_history)

        self._inc_busy()
        threading.Thread(target=worker, daemon=True).start()
        return local_id

    # ----- ENVOI (texte) -----
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
        c.messages.append(item)
        self._render_conversation()
        self._save_history()

        def set_prog(p):
            item["progress"] = p

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
            progress_cb(8)
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

    # ----- ENVOI (fichier / image) -----
    def _send_file_dialog(self):
        c = self.current_conv
        if not c:
            messagebox.showwarning("Info", self.tr("error.no_active_conversation")); return
        path = filedialog.askopenfilename()
        if not path: return

        try:
            with open(path, "rb") as f:
                data = f.read()  # pour l’aperçu local immédiat
        except Exception as e:
            messagebox.showerror("Error", str(e)); return

        filename = os.path.basename(path)
        mime, _ = mimetypes.guess_type(path)
        is_image = bool(mime and mime.startswith("image/"))
        idn = self.ident_store.identities[c.identity_id]
        ts = int(time.time())

        item = {
            "local_id": "",
            "direction":"out",
            "kind":"image" if is_image else "file",
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
            if not buf:
                progress_cb(end); return ""
            chunk = 64 * 1024
            total = len(buf)
            out_parts = []
            done = 0
            carry = b""

            for i in range(0, total, chunk):
                block = carry + buf[i:i+chunk]
                rem = len(block) % 3
                to_enc = block if rem == 0 else block[:-rem]
                if to_enc:
                    out_parts.append(base64.b64encode(to_enc))
                carry = b"" if rem == 0 else block[-rem:]

                done += min(chunk, total - i)
                frac = done / total
                progress_cb(start + (end - start) * frac)

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
            to_sign = canonical_dumps({k:v for k,v in payload.items() if k!="sig"})
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

    # ----- Ajouter le contact courant s'il est inconnu -----
    def _add_contact_from_current(self):
        if not self.current_conv:
            return
        conv = self.current_conv
        if self.contacts.find_by_pub(conv.contact_pub_hex):
            self._update_add_contact_button()
            return
        idents = self.ident_store.list()
        ident_default = conv.identity_id
        dlg = ContactDialog(self.root, idents, self.tr,
                            "contact.title.new", name="", key=conv.contact_pub_hex, identity_id=ident_default)
        self.root.wait_window(dlg)
        if dlg.result:
            name, key, ident_id = dlg.result
            self.contacts.add(name, key, ident_id)
            conv.contact_name = name
            self._refresh_conv_sidebar(select_key=(conv.identity_id, conv.contact_pub_hex))
            self._save_history()

    # ----- Actions -----
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

    # ----- POLLING -----
    def _start_poll_thread(self):
        t = threading.Thread(target=self._poll_loop, daemon=True)
        t.start()

    def _poll_loop(self):
        while True:
            ok = True
            try:
                for idn in self.ident_store.list():
                    self._poll_once_for_identity(idn)
            except Exception:
                ok = False
            self._set_status(ok)
            time.sleep(self.cfg["polling_interval"] + 5 * random.random())

    def _set_status(self, online: bool):
        txt = self.tr("status.online") if online else self.tr("status.offline")
        color = "green" if online else "red"
        try: self.status_lbl.config(text=txt, foreground=color)
        except: pass

    def _poll_once_for_identity(self, idn: Identity):
        url = self.cfg["server_url"].rstrip("/") + "/get/"
        r = signed_post(url, {"recipient": idn.box_pub_hex}, idn.sign_sk, idn.sign_pub_hex)
        if r.status_code != 200: raise RuntimeError("Server unavailable")
        data = r.json()
        ids_to_ack = []
        ids_to_delete = []

        updated = False

        for msg in data.get("messages", []):
            mid = msg["id"]
            if mid in self._seen_ids:
                continue
            self._seen_ids.add(mid)
            cipher_hex = msg["cipher_hex"]
            created_ts = msg.get("created_at", int(time.time()))
            try:
                pt_bytes = decrypt_with(idn.box_sk, cipher_hex)
                payload = json.loads(pt_bytes.decode())
            except Exception:
                continue

            sig_hex = payload.get("sig","")
            to_verify = {k:v for k,v in payload.items() if k!="sig"}
            body_bytes = canonical_dumps(to_verify)
            sender_sign_pub = payload.get("sender_sign_pub","")
            try:
                _VerifyKey(bytes.fromhex(sender_sign_pub)).verify(body_bytes, bytes.fromhex(sig_hex))
            except Exception:
                continue

            kind = payload.get("t")
            sender_box_pub = payload.get("sender_box_pub","")
            contact = self.contacts.find_by_pub(sender_box_pub)
            contact_name = contact["name"] if contact else self.tr("unknown.contact", prefix=sender_box_pub[:6])

            key = (idn.id, sender_box_pub)
            if key not in self.conversations:
                conv = Conversation(idn.id, idn.name, contact_name, sender_box_pub)
                self.conversations[key] = conv
            conv = self.conversations[key]

            if kind == "text":
                text = payload.get("text","")
                conv.messages.append({"direction":"in","kind":"text","text":text,"ts":created_ts})
            elif kind == "image":
                raw = base64.b64decode(payload.get("data_b64",""), validate=True)
                conv.messages.append({"direction":"in","kind":"image","data":raw,"filename":payload.get("filename"),"ts":created_ts})
            else:
                raw = base64.b64decode(payload.get("data_b64",""), validate=True)
                conv.messages.append({"direction":"in","kind":"file","data":raw,"filename":payload.get("filename"),"ts":created_ts})

            if self.current_conv is None or conv is not self.current_conv:
                conv.unread += 1

            ids_to_ack.append(mid)
            if self.secure_var.get():
                ids_to_delete.append(mid)

            updated = True

        if ids_to_ack:
            try:
                url_ack = self.cfg["server_url"].rstrip("/") + "/ack/"
                signed_post(url_ack, {"ids": ids_to_ack}, idn.sign_sk, idn.sign_pub_hex)
            except Exception:
                pass

        if ids_to_delete:
            try:
                url_del = self.cfg["server_url"].rstrip("/") + "/delete/"
                signed_post(url_del, {"ids": ids_to_delete}, idn.sign_sk, idn.sign_pub_hex)
            except Exception:
                pass

        if updated:
            self._refresh_conv_sidebar(select_key=self._current_key)
            self._save_history()

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
                self._seen_ids.clear()
                self.conversations.clear()
                self._current_key = None
                self.ident_store = IdentityStore(bootstrap_default=False)
                self.contacts = ContactsStore()
                self._refresh_conv_sidebar()
            else:
                self.secure_var.set(False)
                self.cfg["secure_mode"] = False
                save_config(self.cfg)
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

# =============== main ===============
if __name__ == "__main__":
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "clam" in style.theme_names(): style.theme_use("clam")
    except Exception:
        pass
    app = MessengerApp(root)
    root.mainloop()
