import json
import logging
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KRLManager:
    def __init__(self, krl_file="krl.json"):
        """
        Initialize the KRL Manager.
        Args:
            krl_file: Path to the KRL file
        """
        self.krl_file = Path(krl_file)
        self.revoked_keys = self._load_krl()

    def _load_krl(self):
        """
        Load the Key Revocation List from file.
        Returns:
            Dictionary containing revoked keys
        """
        try:
            if self.krl_file.exists():
                with open(self.krl_file, 'r') as f:
                    return json.load(f)
            return {}
        except Exception as e:
            logger.error(f"Error loading KRL: {str(e)}")
            return {}

    def _save_krl(self):
        """
        Save the Key Revocation List to file.
        """
        try:
            with open(self.krl_file, 'w') as f:
                json.dump(self.revoked_keys, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving KRL: {str(e)}")

    def revoke_key(self, key_name):
        """
        Revoke a key by adding it to the KRL.
        Args:
            key_name: Name of the key to revoke
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if key_name in self.revoked_keys:
                logger.warning(f"Key {key_name} is already revoked")
                return False

            self.revoked_keys[key_name] = {
                "revocation_date": datetime.now().isoformat(),
                "status": "revoked"
            }
            self._save_krl()
            logger.info(f"Key {key_name} revoked successfully")
            return True
        except Exception as e:
            logger.error(f"Error revoking key {key_name}: {str(e)}")
            return False

    def remove_key_revocation(self, key_name):
        """
        Remove a key from the KRL.
        Args:
            key_name: Name of the key to remove from revocation
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            if key_name not in self.revoked_keys:
                logger.warning(f"Key {key_name} is not in the KRL")
                return False

            del self.revoked_keys[key_name]
            self._save_krl()
            logger.info(f"Key {key_name} removed from KRL successfully")
            return True
        except Exception as e:
            logger.error(f"Error removing key {key_name} from KRL: {str(e)}")
            return False

    def check_key_status(self, key_name):
        """
        Check if a key is revoked.
        Args:
            key_name: Name of the key to check
        Returns:
            bool: True if key is revoked, False otherwise
        """
        return key_name in self.revoked_keys

    def get_key_info(self, key_name):
        """
        Get information about a revoked key.
        Args:
            key_name: Name of the key to get information about
        Returns:
            dict: Key information if found, None otherwise
        """
        return self.revoked_keys.get(key_name)

    def list_revoked_keys(self):
        """
        Get a list of all revoked keys.
        Returns:
            list: List of revoked key names
        """
        return list(self.revoked_keys.keys())

def revoke_key(key_name):
    """
    Wrapper function to revoke a key.
    Args:
        key_name: Name of the key to revoke
    Returns:
        bool: True if successful, False otherwise
    """
    krl = KRLManager()
    return krl.revoke_key(key_name)

def remove_key_revocation(key_name):
    """
    Wrapper function to remove a key from revocation.
    Args:
        key_name: Name of the key to remove from revocation
    Returns:
        bool: True if successful, False otherwise
    """
    krl = KRLManager()
    return krl.remove_key_revocation(key_name)

def check_key_status(key_name):
    """
    Wrapper function to check key revocation status.
    Args:
        key_name: Name of the key to check
    Returns:
        bool: True if key is revoked, False otherwise
    """
    krl = KRLManager()
    return krl.check_key_status(key_name)

if __name__ == "__main__":
    # Test KRL functionality
    test_key = "test_key.pem"
    
    # Test key revocation
    if revoke_key(test_key):
        print(f"Key {test_key} revoked successfully")
        
        # Test key status check
        if check_key_status(test_key):
            print(f"Key {test_key} is revoked")
            
            # Test removing revocation
            if remove_key_revocation(test_key):
                print(f"Key {test_key} removed from KRL")
                
                # Verify removal
                if not check_key_status(test_key):
                    print(f"Key {test_key} is no longer revoked") 