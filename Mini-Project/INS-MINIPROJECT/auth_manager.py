# auth_manager.py

import json
import hashlib
import os

def issue_certificate(username):
    cert_path = f'certificates/{username}_certificate.pem'
    if not os.path.exists('certificates'):
        os.makedirs('certificates')
    if not os.path.exists(cert_path):
        # Generate a simple certificate (for demonstration purposes)
        with open(cert_path, 'w') as f:
            f.write(f'Certificate for {username}')
    return cert_path


def authenticate_user(username, password):
    try:
        with open(f'users/{username}.json', 'r') as f:
            user_data = json.load(f)
    except FileNotFoundError:
        return False, "User does not exist."

    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    if user_data['password_hash'] == password_hash:
        cert_path = issue_certificate(username)
        return True, f"Authentication successful. Certificate issued at {cert_path}."
    else:
        return False, "Authentication failed."
