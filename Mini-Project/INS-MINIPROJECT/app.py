# app.py

from flask import Flask, request, jsonify
import key_manager
import user_manager
import auth_manager
import signer
import revoke_manager

app = Flask(__name__)

@app.route('/generate_aes_key', methods=['POST'])
def generate_aes():
    message = key_manager.generate_aes_key()
    return jsonify({'message': message})

@app.route('/setup_user', methods=['POST'])
def setup_user():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password required.'}), 400

    username = data['username']
    password = data['password']
    message = user_manager.create_user(username, password)
    return jsonify({'message': message})

@app.route('/login_user', methods=['POST'])
def login_user():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'message': 'Username and password required.'}), 400

    username = data['username']
    password = data['password']

    if revoke_manager.is_revoked(username):
        return jsonify({'message': 'User is revoked.'}), 403

    success, message = auth_manager.authenticate_user(username, password)
    if success:
        return jsonify({'message': message})
    else:
        return jsonify({'message': message}), 401

@app.route('/revoke_user', methods=['POST'])
def revoke_user():
    data = request.get_json()
    if not data or 'admin_password' not in data or 'username' not in data:
        return jsonify({'message': 'Admin password and username required.'}), 400

    admin_password = data['admin_password']
    username_to_revoke = data['username']
    message = revoke_manager.revoke_user(admin_password, username_to_revoke)
    return jsonify({'message': message})

@app.route('/sign_message', methods=['POST'])
def sign_message():
    data = request.get_json()
    if not data or 'username' not in data or 'message' not in data:
        return jsonify({'message': 'Username and message required.'}), 400

    username = data['username']
    message_text = data['message']

    signature, msg = signer.sign_message(username, message_text)
    if signature:
        return jsonify({'signature': signature, 'message': msg})
    else:
        return jsonify({'message': msg}), 400

@app.route('/verify_message', methods=['POST'])
def verify_signature():
    data = request.get_json()
    if not data or 'username' not in data or 'signature' not in data:
        return jsonify({'message': 'Username, certificate, and signature required.'}), 400

    username = data['username']
    signature = data['signature']

    msg = signer.verify_message(data)
    if 'error' in msg:
        return jsonify({'message': 'Invalid login'}), 401
    else:
        return jsonify({'message': msg['message']})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
