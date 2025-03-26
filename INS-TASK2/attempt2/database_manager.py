import sqlite3
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class DatabaseManager:
    def __init__(self, db_path="keys.db"):
        self.db_path = db_path
        self.fernet = None
        self._init_db()

    def _init_db(self):
        """Initialize the database with required tables."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                encrypted_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def set_master_key(self, password: str):
        """Set the master key using the provided password."""
        # Generate a key from the password using PBKDF2
        salt = b'fixed_salt'  # In production, use a random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.fernet = Fernet(key)

    def add_user(self, username: str, key: bytes):
        """Add a new user with their encrypted key."""
        if not self.fernet:
            raise ValueError("Master key not set")

        encrypted_key = self.fernet.encrypt(key)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO users (username, encrypted_key) VALUES (?, ?)",
                (username, encrypted_key.decode())
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            conn.close()

    def get_user_key(self, username: str) -> bytes:
        """Retrieve and decrypt a user's key."""
        if not self.fernet:
            raise ValueError("Master key not set")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT encrypted_key FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()

        if not result:
            raise ValueError(f"User {username} not found")

        encrypted_key = result[0].encode()
        return self.fernet.decrypt(encrypted_key)

    def list_users(self):
        """List all users in the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT username, created_at FROM users")
        users = cursor.fetchall()
        conn.close()

        return users

    def delete_user(self, username: str):
        """Delete a user from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
        conn.close() 