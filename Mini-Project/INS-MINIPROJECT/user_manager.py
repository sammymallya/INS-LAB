# user_manager.py

import key_manager
import os
import json
import hashlib

def create_user(username, password):
    if not os.path.exists('users'):
        os.makedirs('users')
    
    if os.path.exists(f'users/{username}.json'):
        return "User already exists."
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    user_data = {
        "username": username,
        "password_hash": password_hash
    }
    
    with open(f'users/{username}.json', 'w') as f:
        json.dump(user_data, f)
    
    key_manager.generate_rsa_keys(username)
    
    return "User created successfully."
