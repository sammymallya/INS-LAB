from cryptography.fernet import Fernet
import base64
import sqlite3
import os

def get_user_key(username: str) -> bytes:
    """
    Retrieve a user's symmetric key from the database.
    
    Args:
        username (str): The username whose key to retrieve
        
    Returns:
        bytes: The user's symmetric key
        
    Raises:
        ValueError: If user not found or key is inactive
    """
    if not os.path.exists('user_keys.db'):
        raise ValueError("Database not found. Please create it first.")
        
    conn = sqlite3.connect('user_keys.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT symmetric_key, is_active FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        
        if not result:
            raise ValueError(f"User {username} not found")
            
        key, is_active = result
        if not is_active:
            raise ValueError(f"Key for user {username} has been revoked")
            
        return key.encode()
    finally:
        conn.close()

def encrypt_message(message: str, username: str) -> str:
    """
    Encrypt a message using the user's symmetric key.
    
    Args:
        message (str): The message to encrypt
        username (str): The username whose key to use for encryption
        
    Returns:
        str: The encrypted message as a base64 encoded string
        
    Raises:
        ValueError: If user not found or key is inactive
    """
    try:
        # Get the user's key
        key = get_user_key(username)
        
        # Create Fernet instance with the key
        f = Fernet(key)
        
        # Encrypt the message
        encrypted_data = f.encrypt(message.encode())
        
        # Return base64 encoded string
        return base64.b64encode(encrypted_data).decode()
        
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_message(encrypted_message: str, username: str) -> str:
    """
    Decrypt a message using the user's symmetric key.
    
    Args:
        encrypted_message (str): The encrypted message as a base64 encoded string
        username (str): The username whose key to use for decryption
        
    Returns:
        str: The decrypted message
        
    Raises:
        ValueError: If user not found, key is inactive, or decryption fails
    """
    try:
        # Get the user's key
        key = get_user_key(username)
        
        # Create Fernet instance with the key
        f = Fernet(key)
        
        # Decode the base64 string and decrypt
        encrypted_data = base64.b64decode(encrypted_message)
        decrypted_data = f.decrypt(encrypted_data)
        
        # Return the decrypted message
        return decrypted_data.decode()
        
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

def main():
    print("Symmetric Encryption/Decryption Demo")
    print("-" * 40)
    
    while True:
        print("\nOptions:")
        print("1. Encrypt Message")
        print("2. Decrypt Message")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == "1":
            username = input("Enter username: ")
            message = input("Enter message to encrypt: ")
            try:
                encrypted = encrypt_message(message, username)
                print(f"\nEncrypted message: {encrypted}")
            except ValueError as e:
                print(f"Error: {e}")
                
        elif choice == "2":
            username = input("Enter username: ")
            encrypted = input("Enter encrypted message: ")
            try:
                decrypted = decrypt_message(encrypted, username)
                print(f"\nDecrypted message: {decrypted}")
            except ValueError as e:
                print(f"Error: {e}")
                
        elif choice == "3":
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main() 