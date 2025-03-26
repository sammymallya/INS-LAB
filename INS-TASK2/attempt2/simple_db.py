import sqlite3
import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
import os

# Global variable for admin password
ADMIN_PASSWORD = "admin123"  # In production, use a secure password storage method

def generate_symmetric_key():
    """Generate a secure symmetric key"""
    return Fernet.generate_key()

def create_database():
    # Delete existing database if it exists
    if os.path.exists('user_keys.db'):
        os.remove('user_keys.db')
    
    # Connect to SQLite database (creates it if it doesn't exist)
    conn = sqlite3.connect('user_keys.db')
    cursor = conn.cursor()
    
    # Create the users table with additional fields
    cursor.execute('''
        CREATE TABLE users (
            username TEXT PRIMARY KEY,
            symmetric_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Commit the changes and close connection
    conn.commit()
    conn.close()
    print("Database created successfully!")

def ensure_database_exists():
    """Ensure database exists before any operation"""
    if not os.path.exists('user_keys.db'):
        create_database()

def add_user():
    # Ensure database exists
    ensure_database_exists()
    
    # Get user input
    username = input("Enter username: ")
    
    # Generate a new symmetric key
    symmetric_key = generate_symmetric_key()
    
    # Connect to database
    conn = sqlite3.connect('user_keys.db')
    cursor = conn.cursor()
    
    try:
        # Insert the new user with their symmetric key
        cursor.execute("INSERT INTO users (username, symmetric_key) VALUES (?, ?)",
                      (username, symmetric_key.decode()))
        conn.commit()
        print(f"\nUser {username} added successfully!")
        print(f"Generated Symmetric Key: {symmetric_key.decode()}")
        print("IMPORTANT: Save this key securely! It won't be shown again.")
    except sqlite3.IntegrityError:
        print("Error: Username already exists!")
    finally:
        conn.close()

def view_database():
    # Ensure database exists
    ensure_database_exists()
    
    # Connect to the database
    conn = sqlite3.connect('user_keys.db')
    cursor = conn.cursor()
    
    # Fetch all records
    cursor.execute("SELECT username, created_at, is_active FROM users")
    rows = cursor.fetchall()
    
    # Print the records
    print("\nCurrent Database Contents:")
    print("Username | Created At | Status")
    print("-" * 60)
    for row in rows:
        status = "Active" if row[2] else "Inactive"
        print(f"{row[0]} | {row[1]} | {status}")
    
    conn.close()

def revoke_key():
    # Ensure database exists
    ensure_database_exists()
    
    username = input("Enter username to revoke key: ")
    
    conn = sqlite3.connect('user_keys.db')
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE users SET is_active = 0 WHERE username = ?", (username,))
        if cursor.rowcount > 0:
            conn.commit()
            print(f"Key for user {username} has been revoked!")
        else:
            print(f"User {username} not found!")
    finally:
        conn.close()

def verify_password(password):
    # Simple password verification (in production, use proper password hashing)
    return password == ADMIN_PASSWORD

def admin_menu():
    while True:
        print("\nAdmin Menu")
        print("1. Create Database")
        print("2. Add New User")
        print("3. View Database")
        print("4. Revoke Key")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == "1":
            create_database()
        elif choice == "2":
            add_user()
        elif choice == "3":
            view_database()
        elif choice == "4":
            revoke_key()
        elif choice == "5":
            print("Logging out...")
            break
        else:
            print("Invalid choice. Please try again.")

def user_menu():
    while True:
        print("\nUser Menu")
        print("1. Add New User")
        print("2. Exit")
        
        choice = input("\nEnter your choice (1-2): ")
        
        if choice == "1":
            add_user()
        elif choice == "2":
            print("Logging out...")
            break
        else:
            print("Invalid choice. Please try again.")

def main():
    while True:
        print("\nWelcome to Symmetric Key Distribution System")
        print("1. Admin Access")
        print("2. User Access")
        print("3. Exit System")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == "1":
            password = input("Enter admin password: ")
            if verify_password(password):
                print("Admin access granted!")
                admin_menu()
            else:
                print("Invalid admin password!")
        
        elif choice == "2":
            print("User access granted!")
            user_menu()
        
        elif choice == "3":
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main() 