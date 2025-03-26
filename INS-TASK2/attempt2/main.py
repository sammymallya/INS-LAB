from database_manager import DatabaseManager
from key_generator import generate_symmetric_key

def main():
    # Initialize the database manager
    db = DatabaseManager()
    
    # Set the master key (password)
    master_password = input("Enter master password: ")
    db.set_master_key(master_password)
    
    while True:
        print("\nKey Distribution System")
        print("1. Add new user")
        print("2. Get user key")
        print("3. List users")
        print("4. Delete user")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == "1":
            username = input("Enter username: ")
            key = generate_symmetric_key()
            if db.add_user(username, key):
                print(f"User {username} added successfully")
                print(f"Generated key (hex): {key.hex()}")
            else:
                print("Username already exists")
                
        elif choice == "2":
            username = input("Enter username: ")
            try:
                key = db.get_user_key(username)
                print(f"Retrieved key (hex): {key.hex()}")
            except ValueError as e:
                print(str(e))
                
        elif choice == "3":
            users = db.list_users()
            print("\nRegistered Users:")
            for username, created_at in users:
                print(f"- {username} (created: {created_at})")
                
        elif choice == "4":
            username = input("Enter username to delete: ")
            db.delete_user(username)
            print(f"User {username} deleted successfully")
            
        elif choice == "5":
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main() 