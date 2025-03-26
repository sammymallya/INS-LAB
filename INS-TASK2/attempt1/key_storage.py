import os
import json
from datetime import datetime
from typing import Dict, Optional
from utils import encrypt_data, decrypt_data, generate_key_id, log_key_operation

class KeyStorage:
    def __init__(self, storage_path: str = "key_store"):
        self.storage_path = storage_path
        self.keys: Dict[str, dict] = {}
        self._ensure_storage_directory()
        self._load_keys()

    def _ensure_storage_directory(self):
        """Ensure the storage directory exists."""
        if not os.path.exists(self.storage_path):
            os.makedirs(self.storage_path)

    def _load_keys(self):
        """Load keys from storage."""
        try:
            with open(os.path.join(self.storage_path, "keys.json"), "r") as f:
                self.keys = json.load(f)
        except FileNotFoundError:
            self.keys = {}

    def _save_keys(self):
        """Save keys to storage."""
        with open(os.path.join(self.storage_path, "keys.json"), "w") as f:
            json.dump(self.keys, f)

    def store_key(self, key: bytes, master_key: bytes, metadata: Optional[dict] = None) -> str:
        """Store a key securely."""
        key_id = generate_key_id()
        
        # Encrypt the key
        encrypted_key = encrypt_data(key, master_key)
        
        # Prepare key metadata
        key_metadata = {
            "encrypted_key": encrypted_key.decode(),
            "created_at": datetime.now().isoformat(),
            "last_used": datetime.now().isoformat(),
            "is_active": True,
            "metadata": metadata or {}
        }
        
        # Store the key
        self.keys[key_id] = key_metadata
        self._save_keys()
        
        log_key_operation("store", key_id, "success")
        return key_id

    def retrieve_key(self, key_id: str, master_key: bytes) -> bytes:
        """Retrieve a key securely."""
        if key_id not in self.keys:
            log_key_operation("retrieve", key_id, "failed", "Key not found")
            raise KeyError(f"Key {key_id} not found")
        
        key_data = self.keys[key_id]
        if not key_data["is_active"]:
            log_key_operation("retrieve", key_id, "failed", "Key is inactive")
            raise KeyError(f"Key {key_id} is inactive")
        
        # Decrypt the key
        encrypted_key = key_data["encrypted_key"].encode()
        decrypted_key = decrypt_data(encrypted_key, master_key)
        
        # Update last used timestamp
        key_data["last_used"] = datetime.now().isoformat()
        self._save_keys()
        
        log_key_operation("retrieve", key_id, "success")
        return decrypted_key

    def revoke_key(self, key_id: str) -> bool:
        """Revoke a key."""
        if key_id not in self.keys:
            log_key_operation("revoke", key_id, "failed", "Key not found")
            return False
        
        self.keys[key_id]["is_active"] = False
        self.keys[key_id]["revoked_at"] = datetime.now().isoformat()
        self._save_keys()
        
        log_key_operation("revoke", key_id, "success")
        return True

    def rotate_key(self, key_id: str, new_key: bytes, master_key: bytes) -> str:
        """Rotate a key with a new one."""
        if key_id not in self.keys:
            log_key_operation("rotate", key_id, "failed", "Key not found")
            raise KeyError(f"Key {key_id} not found")
        
        # Store the new key
        new_key_id = self.store_key(new_key, master_key)
        
        # Mark old key as rotated
        self.keys[key_id]["rotated_to"] = new_key_id
        self.keys[key_id]["rotated_at"] = datetime.now().isoformat()
        self._save_keys()
        
        log_key_operation("rotate", key_id, "success", f"Rotated to {new_key_id}")
        return new_key_id 