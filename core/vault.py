from database.db import Database
from crypto.key_derivation import derive_key
from crypto.cipher import encrypt, decrypt
import os
from datetime import datetime

class Vault:
    def __init__(self, master_password: str):
        self.master_password = master_password
        self.db = Database()

        # First-run: create vault test entry if not exists
        if not self.db.get_meta("vault_test"):
            salt = os.urandom(16)
            key = derive_key(self.master_password, salt)
            test_blob = encrypt(key, b"__vault_test__")
            self.db.set_meta("vault_test", test_blob, salt)

    def _make_salt(self) -> bytes:
        return os.urandom(16)

    # ----- Vault verification -----
    def verify_master_password(self) -> bool:
        meta = self.db.get_meta("vault_test")
        if not meta:
            return True  # first run
        value_blob, salt = meta
        key = derive_key(self.master_password, salt)
        try:
            decrypted = decrypt(key, value_blob)
            return decrypted == b"__vault_test__"
        except Exception:
            return False

    # ----- Entry methods -----
    def add_item(self, title: str, username: str, password: str, notes: str = '') -> int:
        salt = self._make_salt()
        key = derive_key(self.master_password, salt)

        title_blob = encrypt(key, title.encode('utf-8'))
        username_blob = encrypt(key, username.encode('utf-8'))
        password_blob = encrypt(key, password.encode('utf-8'))
        notes_blob = encrypt(key, notes.encode('utf-8')) if notes else b''

        item_id = self.db.add_entry(title_blob, username_blob, password_blob, notes_blob, salt)
        return item_id

    def list_items(self):
        rows = self.db.list_entries()
        result = []
        for row in rows:
            entry_id, title_blob, username_blob, password_blob, notes_blob, salt, created_at, updated_at = row
            key = derive_key(self.master_password, salt)
            try:
                title = decrypt(key, title_blob).decode('utf-8')
                username = decrypt(key, username_blob).decode('utf-8')
                password = decrypt(key, password_blob).decode('utf-8')
                notes = decrypt(key, notes_blob).decode('utf-8') if notes_blob else ''
            except Exception:
                title = '<decryption error>'
                username = password = notes = ''
            result.append({
                'id': entry_id,
                'title': title,
                'username': username,
                'password': password,
                'notes': notes,
                'created_at': created_at,
                'updated_at': updated_at,
            })
        return result

    def get_item(self, entry_id: int):
        row = self.db.get_entry(entry_id)
        if not row:
            return None
        entry_id, title_blob, username_blob, password_blob, notes_blob, salt, created_at, updated_at = row
        key = derive_key(self.master_password, salt)
        try:
            title = decrypt(key, title_blob).decode('utf-8')
            username = decrypt(key, username_blob).decode('utf-8')
            password = decrypt(key, password_blob).decode('utf-8')
            notes = decrypt(key, notes_blob).decode('utf-8') if notes_blob else ''
        except Exception:
            return None
        return {
            'id': entry_id,
            'title': title,
            'username': username,
            'password': password,
            'notes': notes,
            'created_at': created_at,
            'updated_at': updated_at,
        }


    def update_item(self, entry_id: int, title: str, username: str, password: str, notes: str = ''):
        row = self.db.get_entry(entry_id)
        if not row:
            raise ValueError('Entry not found')
        _, _, _, _, _, salt, created_at, _ = row
        key = derive_key(self.master_password, salt)
        title_blob = encrypt(key, title.encode('utf-8'))
        username_blob = encrypt(key, username.encode('utf-8'))
        password_blob = encrypt(key, password.encode('utf-8'))
        notes_blob = encrypt(key, notes.encode('utf-8')) if notes else b''
        # updated_at = datetime.now().isoformat()
        self.db.update_entry(entry_id, title_blob, username_blob, password_blob, notes_blob)

    def delete_item(self, entry_id: int):
        self.db.delete_entry(entry_id)

    def import_item(self, title, username, password, notes="", created_at=None, updated_at=None):
        """Import item while preserving timestamps from JSON."""
        salt = self._make_salt()
        key = derive_key(self.master_password, salt)

        title_blob = encrypt(key, title.encode('utf-8'))
        username_blob = encrypt(key, username.encode('utf-8'))
        password_blob = encrypt(key, password.encode('utf-8'))
        notes_blob = encrypt(key, notes.encode('utf-8')) if notes else b''

        # Default timestamps if missing
        if created_at is None:
            created_at = datetime.utcnow().isoformat()
        if updated_at is None:
            updated_at = created_at

        # Insert directly with preserved timestamps
        return self.db.import_entry(
            title_blob,
            username_blob,
            password_blob,
            notes_blob,
            salt,
            created_at,
            updated_at
        )

