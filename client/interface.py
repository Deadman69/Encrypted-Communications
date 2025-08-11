import os, json
import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Optional, Callable
from nacl.public import PublicKey, PrivateKey
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

# ================== i18n ==================
class I18n:
    def __init__(self, langs_dir: str = "langs", default_lang: str = "en"):
        self.langs_dir = langs_dir
        self.default_lang = default_lang
        os.makedirs(self.langs_dir, exist_ok=True)
        self._bootstrap_default_files()
        self._dict = {}
        self._lang = default_lang
        self.load(default_lang)

    def _bootstrap_default_files(self):
        fr = {
            "app.title": "Messagerie chiffrée",
            "sidebar.conversations": "Conversations",
            "btn.new": "Nouvelle",
            "btn.contacts": "Contacts",
            "btn.identities": "Identités",
            "checkbox.secure": "Mode sécurisé",
            "header.none": "Aucune conversation",
            "status.online": "Serveur: en ligne",
            "status.offline": "Serveur: hors-ligne",

            "menu.help": "Aide",
            "menu.help.source": "Code source",
            "menu.help.license": "Licence (AGPL-3.0-or-later)",
            "menu.help.about": "À propos",
            "about.title": "À propos",
            "about.text": "Encrypted Messaging App\nLicence : AGPL-3.0-or-later\nSource : {url}",

            "menu.lang": "Langue",
            "lang.fr": "Français",
            "lang.en": "English",

            "menu.actions": "Actions",
            "menu.actions.refresh": "Rafraîchir maintenant",
            "menu.actions.settings": "Paramètres…",

            "settings.title": "Paramètres",
            "settings.server_url": "URL du serveur",
            "settings.use_tor": "Utiliser TOR (SOCKS)",
            "settings.socks_proxy": "Proxy SOCKS (ex: socks5h://127.0.0.1:9050)",
            "settings.poll_base": "Polling (base, s)",
            "settings.poll_jitter": "Polling (aléa, s)",

            "info.add_contact_first": "Ajoutez d'abord un contact.",
            "new.chat.title": "Nouvelle conversation",
            "new.chat.prompt": "Tapez le numéro :",
            "new.chat.select_title": "Sélectionner un contact",
            "new.chat.search": "Rechercher…",

            "error.no_active_conversation": "Aucune conversation active.",
            "file.save": "Enregistrer « {filename} »",
            "file.saved_to": "Enregistré dans :\n{path}",
            "confirm.delete_contact": "Supprimer ce contact ?",
            "confirm.delete_identity": "Supprimer l'identité {name} ?",
            "unknown.contact": "Inconnu {prefix}",

            "dlg.ok": "OK",
            "dlg.cancel": "Annuler",
            "dlg.open": "Ouvrir",

            "contact.title.new": "Nouveau contact",
            "contact.title.edit": "Modifier contact",
            "contact.name": "Nom",
            "contact.key": "Clé publique (hex)",
            "contact.identity": "Identité utilisée",

            "contact.new_identity_recommended": "Créer une nouvelle identité (recommandé)",
            "contact.choose_existing_advanced": "Choisir une identité existante (avancé)",
            "contact.new_identity_name": "Nom de la nouvelle identité",

            "error.name_required": "Le nom est requis.",
            "error.invalid_pubkey": "Clé publique invalide.",

            "identities.title": "Identités",
            "contacts.title": "Contacts",
            "btn.add": "Ajouter",
            "btn.rename": "Renommer",
            "btn.edit": "Modifier",
            "btn.delete": "Supprimer",
            "btn.close": "Fermer",

            "btn.copy_my_pub": "Copier ma clé publique",
            "msg.copied": "Copié dans le presse-papiers",
            "adv.toggle": "Mode avancé",
            "adv.box_sk": "Clé privée de chiffrement (hex)",
            "adv.box_pk": "Clé publique de chiffrement (hex, optionnelle)",
            "adv.sign_sk": "Clé privée de signature (hex)",
            "adv.sign_pk": "Clé publique de signature (hex, optionnelle)",
            "error.keys_incomplete": "Clés incomplètes ou invalides (hex 32 octets).",

            "msg.sending": "⌛ Envoi…",
            "msg.sent": "✓ Envoyé",
            "msg.failed": "✗ Échec",
            "msg.cancel": "Annuler l’envoi",
            
            "btn.add_contact_from_msg": "Ajouter le contact",

            "secure.confirm.title": "Mode sécurisé",
            "secure.confirm.text": "Activer le mode sécurisé va supprimer TOUTES les données locales (identités, contacts, conversations). Continuer ?",
            "secure.exit.title": "Quitter – Mode sécurisé",
            "secure.exit.text": "Vous êtes en mode sécurisé. En quittant, TOUTES les données locales (identités, contacts, conversations) seront supprimées. Voulez-vous vraiment quitter ?"
        }
        en = {
            "app.title": "Encrypted Messaging",
            "sidebar.conversations": "Conversations",
            "btn.new": "New",
            "btn.contacts": "Contacts",
            "btn.identities": "Identities",
            "checkbox.secure": "Secure mode",
            "header.none": "No conversation",
            "status.online": "Server: online",
            "status.offline": "Server: offline",

            "menu.help": "Help",
            "menu.help.source": "Source code",
            "menu.help.license": "License (AGPL-3.0-or-later)",
            "menu.help.about": "About",
            "about.title": "About",
            "about.text": "Encrypted Messaging App\nLicense: AGPL-3.0-or-later\nSource: {url}",

            "menu.lang": "Language",
            "lang.fr": "French",
            "lang.en": "English",

            "menu.actions": "Actions",
            "menu.actions.refresh": "Refresh now",
            "menu.actions.settings": "Settings…",

            "settings.title": "Settings",
            "settings.server_url": "Server URL",
            "settings.use_tor": "Use TOR (SOCKS)",
            "settings.socks_proxy": "SOCKS proxy (e.g. socks5h://127.0.0.1:9050)",
            "settings.poll_base": "Polling (base, s)",
            "settings.poll_jitter": "Polling (jitter, s)",

            "info.add_contact_first": "Add a contact first.",
            "new.chat.title": "New conversation",
            "new.chat.prompt": "Type the number:",
            "new.chat.select_title": "Select a contact",
            "new.chat.search": "Search…",

            "error.no_active_conversation": "No active conversation.",
            "file.save": "Save “{filename}”",
            "file.saved_to": "Saved to:\n{path}",
            "confirm.delete_contact": "Delete this contact?",
            "confirm.delete_identity": "Delete identity {name}?",
            "unknown.contact": "Unknown {prefix}",

            "dlg.ok": "OK",
            "dlg.cancel": "Cancel",
            "dlg.open": "Open",

            "contact.title.new": "New contact",
            "contact.title.edit": "Edit contact",
            "contact.name": "Name",
            "contact.key": "Public key (hex)",
            "contact.identity": "Using identity",

            "contact.new_identity_recommended": "Create a new identity (recommended)",
            "contact.choose_existing_advanced": "Choose an existing identity (advanced)",
            "contact.new_identity_name": "New identity name",

            "error.name_required": "Name is required.",
            "error.invalid_pubkey": "Invalid public key.",

            "identities.title": "Identities",
            "contacts.title": "Contacts",
            "btn.add": "Add",
            "btn.rename": "Rename",
            "btn.edit": "Edit",
            "btn.delete": "Delete",
            "btn.close": "Close",

            "btn.copy_my_pub": "Copy my public key",
            "msg.copied": "Copied to clipboard",
            "adv.toggle": "Advanced mode",
            "adv.box_sk": "Encryption private key (hex)",
            "adv.box_pk": "Encryption public key (hex, optional)",
            "adv.sign_sk": "Signing private key (hex)",
            "adv.sign_pk": "Signing public key (hex, optional)",
            "error.keys_incomplete": "Keys are incomplete or invalid (32-byte hex).",

            "msg.sending": "⌛ Sending…",
            "msg.sent": "✓ Sent",
            "msg.failed": "✗ Failed",
            "msg.cancel": "Cancel send",

            "btn.add_contact_from_msg": "Add contact",

            "secure.confirm.title": "Secure mode",
            "secure.confirm.text": "Enabling secure mode will delete ALL local data (identities, contacts, conversations). Continue?",
            "secure.exit.title": "Quit – Secure mode",
            "secure.exit.text": "You are in secure mode. On exit, ALL local data (identities, contacts, conversations) will be deleted. Do you really want to quit?"
        }
        self._write_if_missing("fr.json", fr)
        self._write_if_missing("en.json", en)

    def _write_if_missing(self, filename: str, data: dict):
        path = os.path.join(self.langs_dir, filename)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

    def load(self, lang: str):
        path = os.path.join(self.langs_dir, f"{lang}.json")
        if not os.path.exists(path):
            lang = self.default_lang
            path = os.path.join(self.langs_dir, f"{lang}.json")
        with open(path, "r", encoding="utf-8") as f:
            self._dict = json.load(f)
        self._lang = lang

    def t(self, key: str, **kwargs) -> str:
        text = self._dict.get(key, key)
        if kwargs:
            try:
                text = text.format(**kwargs)
            except Exception:
                pass
        return text

    def current_lang(self) -> str:
        return self._lang

# ================== Settings dialog ==================
class SettingsDialog(tk.Toplevel):
    def __init__(self, parent, tr: Callable[[str], str], cfg: dict):
        super().__init__(parent)
        self.tr = tr
        self.title(self.tr("settings.title")); self.resizable(False, False)
        self.result = None

        frm = ttk.Frame(self, padding=10); frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text=self.tr("settings.server_url")).grid(row=0, column=0, sticky="w")
        self.e_url = ttk.Entry(frm, width=50); self.e_url.grid(row=0, column=1, sticky="ew")
        self.e_url.insert(0, cfg.get("server_url",""))

        self.var_tor = tk.BooleanVar(value=bool(cfg.get("use_tor", True)))
        self.chk_tor = ttk.Checkbutton(
            frm, text=self.tr("settings.use_tor"),
            variable=self.var_tor, command=self._toggle_proxy_state
        )
        self.chk_tor.grid(row=1, column=0, columnspan=2, sticky="w", pady=(6,0))

        ttk.Label(frm, text=self.tr("settings.socks_proxy")).grid(row=2, column=0, sticky="w", pady=(6,0))
        self.e_proxy = ttk.Entry(frm, width=50); self.e_proxy.grid(row=2, column=1, sticky="ew")
        self.e_proxy.insert(0, cfg.get("socks_proxy", "socks5h://127.0.0.1:9050"))

        ttk.Label(frm, text=self.tr("settings.poll_base")).grid(row=3, column=0, sticky="w", pady=(6,0))
        self.e_base = ttk.Entry(frm, width=12); self.e_base.grid(row=3, column=1, sticky="w", pady=(6,0))
        self.e_base.insert(0, str(cfg.get("polling_base", 5)))

        ttk.Label(frm, text=self.tr("settings.poll_jitter")).grid(row=4, column=0, sticky="w", pady=(6,0))
        self.e_jitter = ttk.Entry(frm, width=12); self.e_jitter.grid(row=4, column=1, sticky="w", pady=(6,0))
        self.e_jitter.insert(0, str(cfg.get("polling_jitter", 3)))

        btns = ttk.Frame(frm); btns.grid(row=5, column=0, columnspan=2, pady=(10,0), sticky="e")
        ttk.Button(btns, text=self.tr("dlg.cancel"), command=self.destroy).pack(side="right")
        ttk.Button(btns, text=self.tr("dlg.ok"), command=self._ok).pack(side="right", padx=(0,6))

        # init state
        self._toggle_proxy_state()

        self.bind("<Return>", lambda _e: self._ok())
        self.grab_set(); self.e_url.focus_set()

    def _toggle_proxy_state(self):
        """Disable SOCKS proxy input when TOR is off."""
        self.e_proxy.configure(state=("normal" if self.var_tor.get() else "disabled"))

    def _ok(self):
        try:
            base = float(self.e_base.get().strip())
            jitter = float(self.e_jitter.get().strip())
        except Exception:
            base, jitter = 5.0, 3.0
        self.result = {
            "server_url": self.e_url.get().strip(),
            "use_tor": bool(self.var_tor.get()),
            "socks_proxy": self.e_proxy.get().strip(),
            "polling_base": base,
            "polling_jitter": jitter,
        }
        self.destroy()

# ================== Dialogs: Contact / Identity / Managers ==================
class ContactDialog(tk.Toplevel):
    def __init__(self, parent, identities: List, tr: Callable[[str], str],
                 title_key="contact.title.new", name="", key="", identity_id=None,
                 allow_new_identity: bool = False, fixed_identity_id: Optional[str] = None):
        super().__init__(parent)
        self.tr = tr
        self.title(tr(title_key)); self.resizable(False, False)
        self.result = None

        frm = ttk.Frame(self, padding=10); frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text=self.tr("contact.name")).grid(row=0, column=0, sticky="w")
        self.e_name = ttk.Entry(frm); self.e_name.grid(row=0, column=1, sticky="ew")
        self.e_name.insert(0, name)

        ttk.Label(frm, text=self.tr("contact.key")).grid(row=1, column=0, sticky="w", pady=(6,0))
        self.e_key = ttk.Entry(frm, width=70); self.e_key.grid(row=1, column=1, sticky="ew", pady=(6,0))
        self.e_key.insert(0, key)

        # Identity list
        self.id_map = {idn.name: idn.id for idn in identities}
        names = list(self.id_map.keys()) or ["(none)"]

        # Choice (new/existing). If fixed_identity_id is set, force "existing".
        can_create_new = bool(allow_new_identity and not fixed_identity_id)
        self.choice = tk.StringVar(value=("new" if can_create_new else "existing"))

        rb_row = 2
        if can_create_new:
            rb_new = ttk.Radiobutton(frm, text=self.tr("contact.new_identity_recommended"), variable=self.choice, value="new")
            rb_old = ttk.Radiobutton(frm, text=self.tr("contact.choose_existing_advanced"), variable=self.choice, value="existing")
            rb_new.grid(row=rb_row, column=0, columnspan=2, sticky="w", pady=(8,0))
            rb_old.grid(row=rb_row+1, column=0, columnspan=2, sticky="w")
            next_row = rb_row + 2
        else:
            # No "new" option visible when we must stick to an existing identity
            next_row = rb_row

        # "new identity" zone (hidden if not allowed)
        self.lbl_new = ttk.Label(frm, text=self.tr("contact.new_identity_name"))
        self.e_new_ident = ttk.Entry(frm)
        default_ident = (name or "Contact") + " – Identity"
        self.e_new_ident.insert(0, default_ident)
        if can_create_new:
            self.lbl_new.grid(row=next_row, column=0, sticky="w", pady=(6,0))
            self.e_new_ident.grid(row=next_row, column=1, sticky="ew", pady=(6,0))
            next_row += 1

        # "existing identity" zone
        ttk.Label(frm, text=self.tr("contact.identity")).grid(row=next_row, column=0, sticky="w", pady=(6,0))
        self.cmb = ttk.Combobox(frm, values=names, state="readonly")
        self.cmb.grid(row=next_row, column=1, sticky="ew", pady=(6,0))

        # Choose default identity in combo
        if fixed_identity_id:
            name_default = next((n for n,i in self.id_map.items() if i==fixed_identity_id), names[0])
        elif identity_id:
            name_default = next((n for n,i in self.id_map.items() if i==identity_id), names[0])
        else:
            name_default = names[0]
        self.cmb.set(name_default)

        # If identity is fixed, lock the combobox
        if fixed_identity_id:
            self.cmb.configure(state="disabled")

        # Toggle handler (only when "new" is allowed)
        def _toggle():
            if not can_create_new:
                return
            is_new = (self.choice.get() == "new")
            if is_new:
                self.lbl_new.grid() ; self.e_new_ident.grid()
                self.cmb.grid_remove()
            else:
                self.lbl_new.grid_remove() ; self.e_new_ident.grid_remove()
                self.cmb.grid()
        _toggle()
        if can_create_new:
            self.choice.trace_add("write", lambda *_: _toggle())

        # Buttons
        btns = ttk.Frame(frm); btns.grid(row=next_row+1, column=0, columnspan=2, pady=(10,0), sticky="e")
        ttk.Button(btns, text=self.tr("dlg.cancel"), command=self.destroy).pack(side="right")
        ttk.Button(btns, text=self.tr("dlg.ok"), command=self._ok).pack(side="right", padx=(0,6))

        self.bind("<Return>", lambda _e: self._ok())
        self.grab_set(); self.e_name.focus_set()

    def _ok(self):
        name = self.e_name.get().strip()
        key  = self.e_key.get().strip()
        if not name:
            messagebox.showerror(self.tr("contact.title.new"), self.tr("error.name_required")); return
        try:
            PublicKey(key, encoder=HexEncoder)
        except Exception:
            messagebox.showerror(self.tr("contact.title.new"), self.tr("error.invalid_pubkey")); return

        if hasattr(self, "lbl_new") and self.lbl_new.winfo_ismapped() and self.cmb.winfo_ismapped() == 0:
            # New identity branch (only when allowed & visible)
            new_ident_name = self.e_new_ident.get().strip() or "New identity"
            self.result = (name, key, None, {"create_new": True, "new_name": new_ident_name})
        else:
            id_name = self.cmb.get()
            identity_id = self.id_map.get(id_name)
            self.result = (name, key, identity_id, None)
        self.destroy()

class IdentityDialog(tk.Toplevel):
    """Identity dialog with an Advanced mode for manual key material."""
    def __init__(self, parent, tr: Callable[[str], str], title_key="identities.title",
                 initial_name="", initial_keys=None):
        super().__init__(parent)
        self.tr = tr
        self.title(self.tr(title_key)); self.resizable(False, False)
        self.result = None
        self._initial_keys = initial_keys or {}

        frm = ttk.Frame(self, padding=10); frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text=self.tr("contact.name")).grid(row=0, column=0, sticky="w")
        self.e_name = ttk.Entry(frm); self.e_name.grid(row=0, column=1, sticky="ew")
        self.e_name.insert(0, initial_name or "")

        self.var_adv = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(frm, text=self.tr("adv.toggle"),
                              variable=self.var_adv, command=self._toggle_adv)
        chk.grid(row=1, column=0, columnspan=2, sticky="w", pady=(6,4))

        self.adv = ttk.Frame(frm); self.adv.grid(row=2, column=0, columnspan=2, sticky="ew")
        for i in range(2): self.adv.columnconfigure(i, weight=1)

        ttk.Label(self.adv, text=self.tr("adv.box_sk")).grid(row=0, column=0, sticky="w")
        self.e_box_sk = ttk.Entry(self.adv, width=70); self.e_box_sk.grid(row=0, column=1, sticky="ew")

        ttk.Label(self.adv, text=self.tr("adv.box_pk")).grid(row=1, column=0, sticky="w", pady=(4,0))
        self.e_box_pk = ttk.Entry(self.adv, width=70); self.e_box_pk.grid(row=1, column=1, sticky="ew", pady=(4,0))

        ttk.Label(self.adv, text=self.tr("adv.sign_sk")).grid(row=2, column=0, sticky="w", pady=(4,0))
        self.e_sign_sk = ttk.Entry(self.adv, width=70); self.e_sign_sk.grid(row=2, column=1, sticky="ew", pady=(4,0))

        ttk.Label(self.adv, text=self.tr("adv.sign_pk")).grid(row=3, column=0, sticky="w", pady=(4,0))
        self.e_sign_pk = ttk.Entry(self.adv, width=70); self.e_sign_pk.grid(row=3, column=1, sticky="ew", pady=(4,0))

        if self._initial_keys:
            self.e_box_sk.insert(0, self._initial_keys.get("box_sk_hex",""))
            self.e_box_pk.insert(0, self._initial_keys.get("box_pk_hex",""))
            self.e_sign_sk.insert(0, self._initial_keys.get("sign_sk_hex",""))
            self.e_sign_pk.insert(0, self._initial_keys.get("sign_pk_hex",""))

        self._show_adv(False)

        btns = ttk.Frame(frm); btns.grid(row=3, column=0, columnspan=2, pady=(10,0), sticky="e")
        ttk.Button(btns, text=self.tr("dlg.cancel"), command=self.destroy).pack(side="right")
        ttk.Button(btns, text=self.tr("dlg.ok"), command=self._ok).pack(side="right", padx=(0,6))

        self.bind("<Return>", lambda _e: self._ok())
        self.grab_set(); self.e_name.focus_set()

    def _toggle_adv(self):
        self._show_adv(self.var_adv.get())

    def _show_adv(self, show: bool):
        state = "normal" if show else "disabled"
        for w in (self.e_box_sk, self.e_box_pk, self.e_sign_sk, self.e_sign_pk):
            w.configure(state=state)
        self.adv.grid() if show else self.adv.grid_remove()

    def _ok(self):
        name = self.e_name.get().strip()
        if not name:
            messagebox.showerror(self.tr("identities.title"), self.tr("error.name_required")); return

        out = {"name": name}
        if self.var_adv.get():
            box_sk = (self.e_box_sk.get() or "").strip()
            box_pk = (self.e_box_pk.get() or "").strip()
            sign_sk = (self.e_sign_sk.get() or "").strip()
            sign_pk = (self.e_sign_pk.get() or "").strip()

            def _is_hex_32(s):
                try: return s and len(s)==64 and int(s,16) >= 0
                except: return False

            if not (_is_hex_32(box_sk) and _is_hex_32(sign_sk)):
                messagebox.showerror(self.tr("identities.title"), self.tr("error.keys_incomplete")); return

            if box_pk and not _is_hex_32(box_pk):
                messagebox.showerror(self.tr("identities.title"), self.tr("error.keys_incomplete")); return
            if sign_pk and not _is_hex_32(sign_pk):
                messagebox.showerror(self.tr("identities.title"), self.tr("error.keys_incomplete")); return

            out["keys"] = {
                "box_sk_hex": box_sk,
                "box_pk_hex": box_pk or None,
                "sign_sk_hex": sign_sk,
                "sign_pk_hex": sign_pk or None
            }

        self.result = out
        self.destroy()

# ================== Windows (Managers) ==================
class IdentitiesManager(tk.Toplevel):
    """Identity manager window."""
    def __init__(self, parent, ident_store, tr: Callable[[str], str],
                 on_added: Optional[Callable] = None,
                 on_changed: Optional[Callable] = None):
        super().__init__(parent)
        self.ident_store = ident_store
        self.tr = tr
        self.on_added = on_added
        self.on_changed = on_changed

        self.title(self.tr("identities.title")); self.geometry("640x420")
        frame = ttk.Frame(self, padding=8); frame.pack(fill="both", expand=True)
        self.lb = tk.Listbox(frame, height=12); self.lb.pack(fill="both", expand=True)
        self.lb.bind("<<ListboxSelect>>", lambda _e: self._update_buttons())

        btns = ttk.Frame(frame); btns.pack(fill="x", pady=(8,0))
        ttk.Button(btns, text=self.tr("btn.add"), command=self._add).pack(side="left")
        ttk.Button(btns, text=self.tr("btn.rename"), command=self._rename).pack(side="left", padx=6)
        self.btn_edit = ttk.Button(btns, text=self.tr("btn.edit"), command=self._edit, state="disabled")
        self.btn_edit.pack(side="left")

        self.btn_copy = ttk.Button(btns, text=self.tr("btn.copy_my_pub"),
                                   command=self._copy_my_pub, state="disabled")
        self.btn_copy.pack(side="left", padx=6)

        self.btn_delete = ttk.Button(btns, text=self.tr("btn.delete"), command=self._delete, state="disabled")
        self.btn_delete.pack(side="left")

        ttk.Button(btns, text=self.tr("btn.close"), command=self.destroy).pack(side="right")
        self._refresh()

    def _refresh(self):
        self.lb.delete(0, tk.END)
        for idn in self.ident_store.list():
            short = idn.box_pub_hex[:8] + "…" + idn.box_pub_hex[-8:]
            self.lb.insert(tk.END, f"{idn.name} · {short}")
        self._update_buttons()

    def _current(self):
        sel = self.lb.curselection()
        if not sel:
            return None
        return self.ident_store.list()[sel[0]]

    def _copy_my_pub(self):
        idn = self._current()
        if not idn: return
        try:
            self.clipboard_clear()
            self.clipboard_append(idn.box_pub_hex)
            self.update()
            messagebox.showinfo(self.tr("identities.title"), self.tr("msg.copied"))
        except Exception as e:
            messagebox.showerror(self.tr("identities.title"), str(e))

    def _add(self):
        dlg = IdentityDialog(self, self.tr, "identities.title")
        self.wait_window(dlg)
        if not dlg.result:
            return
        name = dlg.result["name"]
        keys = dlg.result.get("keys")
        try:
            if keys:
                idn = self.ident_store.add_from_material(
                    name=name,
                    box_sk_hex=keys["box_sk_hex"], box_pk_hex=keys.get("box_pk_hex"),
                    sign_sk_hex=keys["sign_sk_hex"], sign_pk_hex=keys.get("sign_pk_hex")
                )
            else:
                idn = self.ident_store.add(name)
            if self.on_added: self.on_added(idn)
            self._refresh()
        except Exception as e:
            messagebox.showerror(self.tr("identities.title"), str(e))

    def _edit(self):
        idn = self._current()
        if not idn: return
        init = {
            "box_sk_hex": idn.box_sk.encode(encoder=HexEncoder).decode(),
            "box_pk_hex": idn.box_pub_hex,
            "sign_sk_hex": idn.sign_sk.encode().hex(),
            "sign_pk_hex": idn.sign_pub_hex
        }
        dlg = IdentityDialog(self, self.tr, "identities.title", initial_name=idn.name, initial_keys=init)
        self.wait_window(dlg)
        if not dlg.result:
            return
        name = dlg.result["name"]
        keys = dlg.result.get("keys")

        try:
            if name and name != idn.name:
                self.ident_store.rename(idn.id, name)
            if keys:
                box_sk_hex = keys["box_sk_hex"]
                box_pk_hex = keys.get("box_pk_hex")
                sign_sk_hex = keys["sign_sk_hex"]
                sign_pk_hex = keys.get("sign_pk_hex")

                if not box_pk_hex:
                    box_pk_hex = PrivateKey(box_sk_hex, encoder=HexEncoder).public_key.encode(encoder=HexEncoder).decode()
                if not sign_pk_hex:
                    sign_pk_hex = SigningKey(bytes.fromhex(sign_sk_hex)).verify_key.encode().hex()

                self.ident_store.replace_keys(
                    idn.id,
                    box_sk_hex=box_sk_hex,
                    box_pk_hex=box_pk_hex,
                    sign_sk_hex=sign_sk_hex,
                    sign_pk_hex=sign_pk_hex
                )
                if self.on_changed:
                    updated = [x for x in self.ident_store.list() if x.id == idn.id][0]
                    self.on_changed(updated)
            self._refresh()
        except Exception as e:
            messagebox.showerror(self.tr("identities.title"), str(e))

    def _rename(self):
        idn = self._current()
        if not idn: return
        dlg = IdentityDialog(self, self.tr, "identities.title", initial_name=idn.name)
        self.wait_window(dlg)
        if dlg.result:
            self.ident_store.rename(idn.id, dlg.result["name"])
            self._refresh()

    def _delete(self):
        idn = self._current()
        if not idn: return
        if messagebox.askyesno(self.tr("identities.title"), self.tr("confirm.delete_identity", name=idn.name)):
            self.ident_store.delete(idn.id)
            self._refresh()

    def _update_buttons(self):
        has = bool(self.lb.curselection())
        state = ("normal" if has else "disabled")
        self.btn_copy.config(state=state)
        self.btn_edit.config(state=state)
        self.btn_delete.config(state=state)

class ContactsManager(tk.Toplevel):
    """Contacts manager window."""
    def __init__(self, parent, contacts_store, identities_store, tr: Callable[[str], str],
                 on_identity_added: Optional[Callable] = None):
        super().__init__(parent)
        self.contacts = contacts_store
        self.ident_store = identities_store
        self.tr = tr
        self.on_identity_added = on_identity_added
        self.title(self.tr("contacts.title")); self.geometry("640x420")

        frame = ttk.Frame(self, padding=8); frame.pack(fill="both", expand=True)
        self.lb = tk.Listbox(frame, height=14); self.lb.grid(row=0, column=0, columnspan=2, sticky="nsew")
        frame.rowconfigure(0, weight=1); frame.columnconfigure(0, weight=1)
        self.lb.bind("<<ListboxSelect>>", lambda _e: self._update_buttons())

        btns = ttk.Frame(frame); btns.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8,0))
        ttk.Button(btns, text=self.tr("btn.add"), command=self._add).pack(side="left")
        self.btn_edit = ttk.Button(btns, text=self.tr("btn.edit"), command=self._edit, state="disabled")
        self.btn_edit.pack(side="left", padx=6)
        self.btn_delete = ttk.Button(btns, text=self.tr("btn.delete"), command=self._delete, state="disabled")
        self.btn_delete.pack(side="left")
        ttk.Button(btns, text=self.tr("btn.close"), command=self.destroy).pack(side="right")
        self._refresh()

    def _refresh(self):
        self.lb.delete(0, tk.END)
        for c in self.contacts.items():
            idn = self.ident_store.identities.get(c["identity_id"])
            idname = idn.name if idn else "?"
            self.lb.insert(tk.END, f"{c['name']} (via {idname}) · {c['pub_hex'][:10]}…{c['pub_hex'][-8:]}")
        self._update_buttons()

    def _update_buttons(self):
        has = bool(self.lb.curselection())
        state = ("normal" if has else "disabled")
        self.btn_edit.config(state=state)
        self.btn_delete.config(state=state)

    def _add(self):
        idents = self.ident_store.list()
        dlg = ContactDialog(self, idents, self.tr, "contact.title.new", allow_new_identity=True)
        self.wait_window(dlg)
        if dlg.result:
            name, key, ident_id, extra = dlg.result
            if extra and extra.get("create_new"):
                idn = self.ident_store.add(extra["new_name"])
                if self.on_identity_added:
                    try: self.on_identity_added(idn)
                    except Exception: pass
                ident_id = idn.id
            self.contacts.add(name, key, ident_id); self._refresh()

    def _edit(self):
        sel = self.lb.curselection()
        if not sel: return
        idx = sel[0]; c = self.contacts.items()[idx]
        idents = self.ident_store.list()
        dlg = ContactDialog(self, idents, self.tr, "contact.title.edit",
                            name=c["name"], key=c["pub_hex"], identity_id=c["identity_id"], allow_new_identity=False)
        self.wait_window(dlg)
        if dlg.result:
            name, key, ident_id, _extra = dlg.result
            self.contacts.update(idx, name, key, ident_id); self._refresh()

    def _delete(self):
        sel = self.lb.curselection()
        if not sel: return
        if messagebox.askyesno(self.tr("contacts.title"), self.tr("confirm.delete_contact")):
            idx = sel[0]
            self.contacts.delete(idx); self._refresh()

class SelectContactDialog(tk.Toplevel):
    def __init__(self, parent, contacts_store, identities_store, tr: Callable[[str], str]):
        super().__init__(parent)
        self.tr = tr
        self.contacts = contacts_store
        self.ident_store = identities_store
        self.result = None

        self.title(self.tr("new.chat.select_title")); self.geometry("560x420"); self.resizable(True, True)
        frm = ttk.Frame(self, padding=10); frm.pack(fill="both", expand=True)
        frm.rowconfigure(2, weight=1); frm.columnconfigure(0, weight=1)

        self.search_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.search_var).grid(row=0, column=0, sticky="ew", pady=(0,8))
        self.search_var.trace_add("write", lambda *_: self._refresh())

        self.lb = tk.Listbox(frm, activestyle="dotbox"); self.lb.grid(row=2, column=0, sticky="nsew")
        self.lb.bind("<<ListboxSelect>>", lambda _e: self._update_open_button())
        self.lb.bind("<Double-Button-1>", lambda _e: self._ok())

        btns = ttk.Frame(frm); btns.grid(row=3, column=0, sticky="e", pady=(8,0))
        ttk.Button(btns, text=self.tr("dlg.cancel"), command=self.destroy).pack(side="right")
        self.btn_open = ttk.Button(btns, text=self.tr("dlg.open"), command=self._ok)
        self.btn_open.pack(side="right", padx=(0,6))

        self._refresh()
        self.grab_set()

    def _refresh(self):
        query = self.search_var.get().strip().lower()
        self.lb.delete(0, tk.END)
        self._idx_to_contact = []
        for c in self.contacts.items():
            idn = self.ident_store.identities.get(c["identity_id"])
            name = c["name"]; ident = idn.name if idn else "?"
            label = f"{name} (via {ident}) · {c['pub_hex'][:10]}…{c['pub_hex'][-8:]}"
            if not query or query in label.lower():
                self.lb.insert(tk.END, label)
                self._idx_to_contact.append(c)
        # update open button based on results & selection
        self._update_open_button()

    def _update_open_button(self):
        sel = bool(self.lb.curselection())
        count = len(getattr(self, "_idx_to_contact", []))
        enable = sel or (count == 1)
        self.btn_open.config(state=("normal" if enable else "disabled"))

    def _ok(self):
        sel = self.lb.curselection()
        if not sel:
            # allow if exactly one contact in the filtered list
            if len(self._idx_to_contact) == 1:
                self.result = self._idx_to_contact[0]
                self.destroy()
            return
        self.result = self._idx_to_contact[sel[0]]
        self.destroy()
