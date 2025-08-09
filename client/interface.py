import os, json
import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Optional, Callable
from nacl.public import PublicKey
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
            "error.name_required": "Le nom est requis.",
            "error.invalid_pubkey": "Clé publique invalide.",

            "identities.title": "Identités",
            "contacts.title": "Contacts",
            "btn.add": "Ajouter",
            "btn.rename": "Renommer",
            "btn.edit": "Modifier",
            "btn.delete": "Supprimer",
            "btn.close": "Fermer",

            "msg.sending": "⌛ Envoi…",
            "msg.sent": "✓ Envoyé",
            "msg.failed": "✗ Échec",

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
            "error.name_required": "Name is required.",
            "error.invalid_pubkey": "Invalid public key.",

            "identities.title": "Identities",
            "contacts.title": "Contacts",
            "btn.add": "Add",
            "btn.rename": "Rename",
            "btn.edit": "Edit",
            "btn.delete": "Delete",
            "btn.close": "Close",

            "msg.sending": "⌛ Sending…",
            "msg.sent": "✓ Sent",
            "msg.failed": "✗ Failed",

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
    def __init__(self, parent, identities: List, tr: Callable[[str], str], title_key="contact.title.new", name="", key="", identity_id=None):
        super().__init__(parent)
        self.tr = tr
        self.title(tr(title_key)); self.resizable(False, False)
        self.result = None

        frm = ttk.Frame(self, padding=10); frm.pack(fill="both", expand=True)
        frm.columnconfigure(1, weight=1)

        ttk.Label(frm, text=tr("contact.name")).grid(row=0, column=0, sticky="w")
        self.e_name = ttk.Entry(frm); self.e_name.grid(row=0, column=1, sticky="ew")
        self.e_name.insert(0, name)

        ttk.Label(frm, text=tr("contact.key")).grid(row=1, column=0, sticky="w", pady=(6,0))
        self.e_key = ttk.Entry(frm, width=70); self.e_key.grid(row=1, column=1, sticky="ew", pady=(6,0))
        self.e_key.insert(0, key)

        ttk.Label(frm, text=tr("contact.identity")).grid(row=2, column=0, sticky="w", pady=(6,0))
        self.id_map = {idn.name: idn.id for idn in identities}
        names = list(self.id_map.keys()) or ["(none)"]
        self.cmb = ttk.Combobox(frm, values=names, state="readonly")
        self.cmb.grid(row=2, column=1, sticky="ew", pady=(6,0))
        if identity_id:
            name_default = next((n for n,i in self.id_map.items() if i==identity_id), names[0])
        else:
            name_default = names[0]
        self.cmb.set(name_default)

        btns = ttk.Frame(frm); btns.grid(row=3, column=0, columnspan=2, pady=(10,0), sticky="e")
        ttk.Button(btns, text=tr("dlg.cancel"), command=self.destroy).pack(side="right")
        ttk.Button(btns, text=tr("dlg.ok"), command=self._ok).pack(side="right", padx=(0,6))

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
        id_name = self.cmb.get()
        identity_id = self.id_map.get(id_name)
        self.result = (name, key, identity_id); self.destroy()

class IdentityDialog(tk.Toplevel):
    def __init__(self, parent, tr: Callable[[str], str], title_key="identities.title", initial_name=""):
        super().__init__(parent)
        self.tr = tr
        self.title(self.tr(title_key)); self.resizable(False, False)
        self.result = None

        frm = ttk.Frame(self, padding=10); frm.pack(fill="both", expand=True)
        ttk.Label(frm, text=self.tr("contact.name")).grid(row=0, column=0, sticky="w")
        self.e = ttk.Entry(frm); self.e.grid(row=0, column=1, sticky="ew"); self.e.insert(0, initial_name or "")
        frm.columnconfigure(1, weight=1)

        btns = ttk.Frame(frm); btns.grid(row=1, column=0, columnspan=2, pady=(10,0), sticky="e")
        ttk.Button(btns, text=self.tr("dlg.cancel"), command=self.destroy).pack(side="right")
        ttk.Button(btns, text=self.tr("dlg.ok"), command=self._ok).pack(side="right", padx=(0,6))

        self.bind("<Return>", lambda _e: self._ok()); self.grab_set(); self.e.focus_set()

    def _ok(self):
        name = self.e.get().strip()
        if not name:
            messagebox.showerror(self.tr("identities.title"), self.tr("error.name_required")); return
        self.result = name; self.destroy()

# ================== Windows (Managers) ==================
class IdentitiesManager(tk.Toplevel):
    def __init__(self, parent, ident_store, tr: Callable[[str], str], on_added: Optional[Callable] = None):
        super().__init__(parent)
        self.ident_store = ident_store
        self.tr = tr
        self.on_added = on_added
        self.title(self.tr("identities.title")); self.geometry("520x380")
        frame = ttk.Frame(self, padding=8); frame.pack(fill="both", expand=True)
        self.lb = tk.Listbox(frame, height=12); self.lb.pack(fill="both", expand=True)

        btns = ttk.Frame(frame); btns.pack(fill="x", pady=(8,0))
        ttk.Button(btns, text=self.tr("btn.add"), command=self._add).pack(side="left")
        ttk.Button(btns, text=self.tr("btn.rename"), command=self._rename).pack(side="left", padx=6)
        ttk.Button(btns, text=self.tr("btn.delete"), command=self._delete).pack(side="left")
        ttk.Button(btns, text=self.tr("btn.close"), command=self.destroy).pack(side="right")
        self._refresh()

    def _refresh(self):
        self.lb.delete(0, tk.END)
        for idn in self.ident_store.list():
            short = idn.box_pub_hex[:8] + "…" + idn.box_pub_hex[-8:]
            self.lb.insert(tk.END, f"{idn.name} · {short}")

    def _add(self):
        dlg = IdentityDialog(self, self.tr, "identities.title")
        self.wait_window(dlg)
        if dlg.result:
            idn = self.ident_store.add(dlg.result)
            if self.on_added: self.on_added(idn)
            self._refresh()

    def _rename(self):
        sel = self.lb.curselection()
        if not sel: return
        idn = self.ident_store.list()[sel[0]]
        dlg = IdentityDialog(self, self.tr, "identities.title", initial_name=idn.name)
        self.wait_window(dlg)
        if dlg.result:
            self.ident_store.rename(idn.id, dlg.result)
            self._refresh()

    def _delete(self):
        sel = self.lb.curselection()
        if not sel: return
        idn = self.ident_store.list()[sel[0]]
        if messagebox.askyesno(self.tr("identities.title"), self.tr("confirm.delete_identity", name=idn.name)):
            self.ident_store.delete(idn.id)
            self._refresh()

class ContactsManager(tk.Toplevel):
    def __init__(self, parent, contacts_store, identities_store, tr: Callable[[str], str]):
        super().__init__(parent)
        self.contacts = contacts_store
        self.ident_store = identities_store
        self.tr = tr
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
        dlg = ContactDialog(self, idents, self.tr, "contact.title.new")
        self.wait_window(dlg)
        if dlg.result:
            name, key, ident_id = dlg.result
            self.contacts.add(name, key, ident_id); self._refresh()

    def _edit(self):
        sel = self.lb.curselection()
        if not sel: return
        idx = sel[0]; c = self.contacts.items()[idx]
        idents = self.ident_store.list()
        dlg = ContactDialog(self, idents, self.tr, "contact.title.edit", name=c["name"], key=c["pub_hex"], identity_id=c["identity_id"])
        self.wait_window(dlg)
        if dlg.result:
            name, key, ident_id = dlg.result
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
            label = f"{name} (via {ident}) · {c['pub_hex']:{''}}"
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
