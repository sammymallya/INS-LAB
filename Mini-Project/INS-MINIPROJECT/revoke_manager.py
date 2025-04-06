# revoke_manager.py

import json
import os

ADMIN_PASSWORD = "admin123"  # <-- You can change this securely later

def revoke_user(admin_password, username_to_revoke):
    if admin_password != ADMIN_PASSWORD:
        return "Admin password incorrect."
    
    if not os.path.exists('revoked_users.json'):
        revoked_users = []
    else:
        with open('revoked_users.json', 'r') as f:
            revoked_users = json.load(f)
    
    if username_to_revoke not in revoked_users:
        revoked_users.append(username_to_revoke)
    
    with open('revoked_users.json', 'w') as f:
        json.dump(revoked_users, f)
    
    return f"User {username_to_revoke} revoked successfully."

def is_revoked(username):
    if not os.path.exists('revoked_users.json'):
        return False
    with open('revoked_users.json', 'r') as f:
        revoked_users = json.load(f)
    return username in revoked_users
