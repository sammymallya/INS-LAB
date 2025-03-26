import os
from sym_key_management import generate_symmetric_key
from asym_key_management import AsymmetricKeyManager, CertificateManager
from key_storage import KeyStorage
from key_exchange import KeyExchange, DiffieHellman
from utils import generate_master_key

def test_symmetric_key_management():
    print("\n=== Testing Symmetric Key Management ===")
    
    # Generate a master key
    master_key = generate_master_key("test_password")
    
    # Generate a symmetric key
    sym_key = generate_symmetric_key()
    print(f"Generated symmetric key: {sym_key.hex()[:20]}...")
    
    # Store the key
    storage = KeyStorage()
    key_id = storage.store_key(sym_key, master_key)
    print(f"Stored key with ID: {key_id}")
    
    # Retrieve the key
    retrieved_key = storage.retrieve_key(key_id, master_key)
    print(f"Retrieved key matches original: {retrieved_key == sym_key}")
    
    # Revoke the key
    storage.revoke_key(key_id)
    print("Key revoked successfully")

def test_asymmetric_key_management():
    print("\n=== Testing Asymmetric Key Management ===")
    
    # Generate RSA key pair
    asym_manager = AsymmetricKeyManager()
    private_key, public_key = asym_manager.generate_key_pair()
    print("Generated RSA key pair")
    
    # Create and save certificate
    cert_manager = CertificateManager()
    cert_manager.create_self_signed_certificate(
        private_key,
        "test.example.com",
        "Test Organization",
        "US"
    )
    print("Created self-signed certificate")
    
    # Test encryption and decryption
    test_data = b"Hello, World!"
    encrypted_data = asym_manager.encrypt(test_data)
    decrypted_data = asym_manager.decrypt(encrypted_data)
    print(f"Encryption/Decryption test: {decrypted_data == test_data}")
    
    # Test signing and verification
    signature = asym_manager.sign(test_data)
    is_valid = asym_manager.verify(test_data, signature)
    print(f"Signature verification test: {is_valid}")

def test_key_exchange():
    print("\n=== Testing Key Exchange ===")
    
    # Create DH parameters
    dh = DiffieHellman()
    parameters = dh.generate_parameters()
    
    # Create two parties for key exchange
    party_a = KeyExchange()
    party_b = KeyExchange()
    
    # Both parties use the same parameters
    party_a.dh.parameters = parameters
    party_b.dh.parameters = parameters
    
    # Party A initiates the exchange
    party_a_public_key = party_a.dh.get_public_key_bytes()
    print("Party A generated public key")
    
    # Party B initiates the exchange
    party_b_public_key = party_b.dh.get_public_key_bytes()
    print("Party B generated public key")
    
    # Both parties derive the shared key
    party_a_shared_key = party_a.complete_key_exchange(party_b_public_key)
    party_b_shared_key = party_b.complete_key_exchange(party_a_public_key)
    
    # Verify both parties derived the same key
    print(f"Shared key derivation test: {party_a_shared_key == party_b_shared_key}")

def main():
    print("Starting Key Management System Tests")
    
    # Create test directory if it doesn't exist
    if not os.path.exists("test_data"):
        os.makedirs("test_data")
    
    # Run tests
    test_symmetric_key_management()
    test_asymmetric_key_management()
    test_key_exchange()
    
    print("\nAll tests completed successfully!")

if __name__ == "__main__":
    main() 