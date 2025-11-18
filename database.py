# database.py
import sqlite3
import os
import hashlib
import binascii
from datetime import datetime

DB_PATH = "pixelwhisper.db"
PBKDF2_ITER = 150_000

# ---------------- init db ----------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # users table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    # history table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        filename TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)

    conn.commit()
    conn.close()

# ---------------- hashing helpers ----------------
def hash_password(password, salt=None):
    """Return (hash_hex, salt_hex)."""
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = binascii.unhexlify(salt)

    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITER)
    return binascii.hexlify(dk).decode(), binascii.hexlify(salt).decode()

def verify_password(password, stored_hash_hex, stored_salt_hex):
    new_hash, _ = hash_password(password, stored_salt_hex)
    return new_hash == stored_hash_hex

# ---------------- user functions ----------------
def create_user(username: str, password: str):
    """Create user. Returns (ok: bool, message: str)"""
    username = username.strip().lower()
    if not username or not password:
        return False, "Username and password required."
    if len(password) < 4:
        return False, "Password too short (min 4 characters)."

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone():
            return False, "Username already exists."

        pwd_hash, salt = hash_password(password)
        created_at = datetime.utcnow().isoformat()
        cur.execute(
            "INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
            (username, pwd_hash, salt, created_at)
        )
        conn.commit()
        return True, "Registration successful. Please login."
    except Exception as e:
        return False, f"Error: {str(e)}"
    finally:
        conn.close()

def verify_user(username: str, password: str):
    """
    Verify login.
    Returns (ok: bool, user_id: int or None, message: str)
    """
    username = username.strip().lower()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if not row:
            return False, None, "User not found."
        user_id, stored_hash, stored_salt = row
        if verify_password(password, stored_hash, stored_salt):
            return True, user_id, "Login successful."
        else:
            return False, None, "Incorrect password."
    finally:
        conn.close()

# ---------------- history functions ----------------
def add_history(user_id: int, action: str, filename: str = None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    ts = datetime.utcnow().strftime("%Y-%m-%d %I:%M %p")
    cur.execute("INSERT INTO history (user_id, action, filename, timestamp) VALUES (?, ?, ?, ?)",
                (user_id, action, filename, ts))
    conn.commit()
    conn.close()

def get_history(user_id: int, limit: int = 200):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT action, filename, timestamp FROM history WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                (user_id, limit))
    rows = cur.fetchall()
    conn.close()
    return rows

def clear_history(user_id: int):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM history WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

# initialize DB on import
init_db()
