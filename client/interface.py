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

# ================== Dialogs ==================
class ContactDialog(tk.Toplevel):
    def __init__(self, parent, identities: List, tr: Callable[[str], str],
                 title_key="contact.title.new", name="", key="", identity_id=None,
                 allow_new_identity: bool = False):
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

        # --- Choix identité (nouvelle par défaut) ---
        self.choice = tk.StringVar(value=("new" if allow_new_identity else "existing"))
        rb_new = ttk.Radiobutton(frm, text=self.tr("contact.new_identity_recommended"),
                                 variable=self.choice, value="new")
        rb_old = ttk.Radiobutton(frm, text=self.tr("contact.choose_existing_advanced"),
                                 variable=self.choice, value="existing")
        rb_new.grid(row=2, column=0, columnspan=2, sticky="w", pady=(8,0))
        rb_old.grid(row=3, column=0, columnspan=2, sticky="w")

        # zone "nouvelle identité"
        self.lbl_new = ttk.Label(frm, text=self.tr("contact.new_identity_name"))
        self.e_new_ident = ttk.Entry(frm)
        default_ident = (name or "Contact") + " – Identité"
        self.e_new_ident.insert(0, default_ident)
        self.lbl_new.grid(row=4, column=0, sticky="w", pady=(6,0))
        self.e_new_ident.grid(row=4, column=1, sticky="ew", pady=(6,0))

        # zone "existante"
        ttk.Label(frm, text=self.tr("contact.identity")).grid(row=5, column=0, sticky="w", pady=(6,0))
        self.id_map = {idn.name: idn.id for idn in identities}
        names = list(self.id_map.keys()) or ["(none)"]
        self.cmb = ttk.Combobox(frm, values=names, state="readonly")
        self.cmb.grid(row=5, column=1, sticky="ew", pady=(6,0))
        if identity_id:
            name_default = next((n for n,i in self.id_map.items() if i==identity_id), names[0])
        else:
            name_default = names[0]
        self.cmb.set(name_default)

        def _toggle():
            is_new = (self.choice.get() == "new")
            for w in (self.lbl_new, self.e_new_ident):
                w.grid() if is_new else w.grid_remove()
            self.cmb.grid() if not is_new else self.cmb.grid_remove()
        _toggle()
        self.choice.trace_add("write", lambda *_: _toggle())

        btns = ttk.Frame(frm); btns.grid(row=6, column=0, columnspan=2, pady=(10,0), sticky="e")
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

        if self.choice.get() == "new":
            new_ident_name = self.e_new_ident.get().strip() or "Nouvelle identité"
            self.result = (name, key, None, {"create_new": True, "new_name": new_ident_name})
        else:
            id_name = self.cmb.get()
            identity_id = self.id_map.get(id_name)
            self.result = (name, key, identity_id, None)
        self.destroy()

class IdentityDialog(tk.Toplevel):
    """
    Dialogue d'identité avec Mode Avancé (saisie manuelle des clés).
    - En mode simple: seul le nom.
    - En mode avancé: box_sk (+ optionnel box_pk), sign_sk (+ optionnel sign_pk).
    """
    def __init__(self, parent, tr: Callable[[str], str], title_key="identities.title",
                 initial_name="", initial_keys=None):
        super().__init__(parent)
        self.tr = tr
        self.title(self.tr(title_key)); self.resizable(False, False)
        self.result = None
        self._initial_keys = initial_keys or {}

        frm = ttk.Frame(self, padding=10); frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)

        # Nom
        ttk.Label(frm, text=self.tr("contact.name")).grid(row=0, column=0, sticky="w")
        self.e_name = ttk.Entry(frm); self.e_name.grid(row=0, column=1, sticky="ew")
        self.e_name.insert(0, initial_name or "")

        # Toggle avancé
        self.var_adv = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(frm, text=self.tr("adv.toggle"),
                              variable=self.var_adv, command=self._toggle_adv)
        chk.grid(row=1, column=0, columnspan=2, sticky="w", pady=(6,4))

        # Zone avancée
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

        # Pré-remplissage si édition
        if self._initial_keys:
            self.e_box_sk.insert(0, self._initial_keys.get("box_sk_hex",""))
            self.e_box_pk.insert(0, self._initial_keys.get("box_pk_hex",""))
            self.e_sign_sk.insert(0, self._initial_keys.get("sign_sk_hex",""))
            self.e_sign_pk.insert(0, self._initial_keys.get("sign_pk_hex",""))

        # Masquer au démarrage
        self._show_adv(False)

        # Boutons
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

            # Exiger au moins les PRIVÉES
            if not (_is_hex_32(box_sk) and _is_hex_32(sign_sk)):
                messagebox.showerror(self.tr("identities.title"), self.tr("error.keys_incomplete")); return

            # Les publiques sont optionnelles (recalculées si absentes)
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
    """Fenêtre de gestion des identités."""
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

        # activer/désactiver selon la sélection
        self.lb.bind("<<ListboxSelect>>", lambda _e: self._update_buttons())

        btns = ttk.Frame(frame); btns.pack(fill="x", pady=(8,0))
        ttk.Button(btns, text=self.tr("btn.add"), command=self._add).pack(side="left")
        ttk.Button(btns, text=self.tr("btn.rename"), command=self._rename).pack(side="left", padx=6)
        ttk.Button(btns, text=self.tr("btn.edit"), command=self._edit).pack(side="left")

        self.btn_copy = ttk.Button(btns, text=self.tr("btn.copy_my_pub"),
                                   command=self._copy_my_pub)
        self.btn_copy.pack(side="left", padx=6)
        self.btn_copy.config(state="disabled")

        ttk.Button(btns, text=self.tr("btn.delete"), command=self._delete).pack(side="left")
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
                # Compléter pubkeys si absentes
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
        self.btn_copy.config(state=("normal" if has else "disabled"))

class ContactsManager(tk.Toplevel):
    """Fenêtre de gestion des contacts."""
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

        btns = ttk.Frame(frame); btns.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8,0))
        ttk.Button(btns, text=self.tr("btn.add"), command=self._add).pack(side="left")
        ttk.Button(btns, text=self.tr("btn.edit"), command=self._edit).pack(side="left", padx=6)
        ttk.Button(btns, text=self.tr("btn.delete"), command=self._delete).pack(side="left")
        ttk.Button(btns, text=self.tr("btn.close"), command=self.destroy).pack(side="right")
        self._refresh()

    def _refresh(self):
        self.lb.delete(0, tk.END)
        for c in self.contacts.items():
            idn = self.ident_store.identities.get(c["identity_id"])
            idname = idn.name if idn else "?"
            self.lb.insert(tk.END, f"{c['name']} (via {idname}) · {c['pub_hex'][:10]}…{c['pub_hex'][-8:]}")

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

# --------- Sélection de contact (nouvelle conversation) ---------
class SelectContactDialog(tk.Toplevel):
    def __init__(self, parent, contacts_store, identities_store, tr: Callable[[str], str]):
        super().__init__(parent)
        self.tr = tr
        self.contacts = contacts_store
        self.ident_store = identities_store
        self.result = None

        self.title(tr("new.chat.select_title")); self.geometry("560x420"); self.resizable(True, True)
        frm = ttk.Frame(self, padding=10); frm.pack(fill="both", expand=True)
        frm.rowconfigure(2, weight=1); frm.columnconfigure(0, weight=1)

        self.search_var = tk.StringVar()
        ttk.Entry(frm, textvariable=self.search_var).grid(row=0, column=0, sticky="ew", pady=(0,8))
        self.search_var.trace_add("write", lambda *_: self._refresh())

        self.lb = tk.Listbox(frm, activestyle="dotbox"); self.lb.grid(row=2, column=0, sticky="nsew")
        self.lb.bind("<Double-Button-1>", lambda _e: self._ok())

        btns = ttk.Frame(frm); btns.grid(row=3, column=0, sticky="e", pady=(8,0))
        ttk.Button(btns, text=tr("dlg.cancel"), command=self.destroy).pack(side="right")
        ttk.Button(btns, text=tr("dlg.open"), command=self._ok).pack(side="right", padx=(0,6))

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

    def _ok(self):
        sel = self.lb.curselection()
        if not sel:
            return
        self.result = self._idx_to_contact[sel[0]]
        self.destroy()
