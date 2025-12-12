import sqlite3
from pathlib import Path
import datetime
import os

DB_FILE = Path.home() / '.local_password_manager' / 'vault.db'
DB_FILE.parent.mkdir(parents=True, exist_ok=True)

CREATE_TABLE_SQL = '''
CREATE TABLE IF NOT EXISTS entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title BLOB NOT NULL,
    username BLOB NOT NULL,
    password BLOB NOT NULL,
    notes BLOB,
    salt BLOB NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
)
'''

CREATE_META_TABLE_SQL = '''
CREATE TABLE IF NOT EXISTS vault_meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL,
    salt BLOB NOT NULL
)
'''

class Database:
    def __init__(self, db_path: Path = DB_FILE):
        self.db_path = db_path
        self.conn = sqlite3.connect(str(db_path))
        self._init_db()

    def _init_db(self):
        cur = self.conn.cursor()
        cur.execute(CREATE_TABLE_SQL)
        cur.execute(CREATE_META_TABLE_SQL)
        self.conn.commit()

    # ----- Entry methods -----
    def add_entry(self, title_blob: bytes, username_blob: bytes, password_blob: bytes, notes_blob: bytes, salt: bytes):
        # now = datetime.datetime.utcnow().isoformat()
        now = datetime.datetime.now().astimezone().isoformat()
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO entries (title, username, password, notes, salt, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (title_blob, username_blob, password_blob, notes_blob, salt, now, now)
        )
        self.conn.commit()
        return cur.lastrowid
    
    def import_entry(self, title_blob: bytes, username_blob: bytes, password_blob: bytes,
                 notes_blob: bytes, salt: bytes, created_at: str, updated_at: str):
        """Insert an entry keeping original timestamps (used for JSON import)."""
        cur = self.conn.cursor()
        cur.execute(
            'INSERT INTO entries (title, username, password, notes, salt, created_at, updated_at) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (title_blob, username_blob, password_blob, notes_blob, salt, created_at, updated_at)
        )
        self.conn.commit()
        return cur.lastrowid


    def update_entry(self, entry_id: int, title_blob: bytes, username_blob: bytes, password_blob: bytes, notes_blob: bytes):
        # now = datetime.datetime.utcnow().isoformat()
        now = datetime.datetime.now().astimezone().isoformat()
        cur = self.conn.cursor()
        cur.execute(
            'UPDATE entries SET title=?, username=?, password=?, notes=?, updated_at=? WHERE id=?',
            (title_blob, username_blob, password_blob, notes_blob, now, entry_id)
        )
        self.conn.commit()

    def delete_entry(self, entry_id: int):
        cur = self.conn.cursor()
        cur.execute('DELETE FROM entries WHERE id=?', (entry_id,))
        self.conn.commit()

    def list_entries(self):
        cur = self.conn.cursor()
        cur.execute('SELECT id, title, username, password, notes, salt, created_at, updated_at FROM entries ORDER BY id DESC')
        return cur.fetchall()

    def get_entry(self, entry_id: int):
        cur = self.conn.cursor()
        cur.execute('SELECT id, title, username, password, notes, salt, created_at, updated_at FROM entries WHERE id=?', (entry_id,))
        return cur.fetchone()

    # ----- Vault meta methods -----
    def set_meta(self, key: str, value: bytes, salt: bytes):
        cur = self.conn.cursor()
        cur.execute('REPLACE INTO vault_meta (key, value, salt) VALUES (?, ?, ?)', (key, value, salt))
        self.conn.commit()

    def get_meta(self, key: str):
        cur = self.conn.cursor()
        cur.execute('SELECT value, salt FROM vault_meta WHERE key=?', (key,))
        row = cur.fetchone()
        return row if row else None
