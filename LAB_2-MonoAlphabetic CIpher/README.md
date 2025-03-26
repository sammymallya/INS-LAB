# LAB-2: MonoAlphabetic Cipher

## Overview
This repository contains an implementation of the **MonoAlphabetic Cipher**, a substitution cipher where each letter in the plaintext is replaced by a fixed different letter in the alphabet.

## Features
- Encrypts and decrypts text using a fixed substitution mapping.
- Supports custom key mappings for encryption.
- Works with uppercase and lowercase letters.
- Ignores non-alphabetic characters.

## Usage
### Encryption
Run the script and input the plaintext along with the substitution key to obtain the encrypted text.

### Decryption
Provide the ciphertext and the substitution key to retrieve the original message.

## Code Structure
- `monoalphabetic_cipher.py` - Contains the implementation of the MonoAlphabetic Cipher.
- `README.md` - Documentation for the project.

## Example
```python
# Example usage
plaintext = "HELLO WORLD"
key = { 'A': 'Q', 'B': 'W', 'C': 'E', ..., 'Z': 'M' }
ciphertext = encrypt(plaintext, key)
print("Encrypted:", ciphertext)
```

## Requirements
- Python 3.x

## How to Run
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/LAB-2-MonoAlphabetic-Cipher.git
   ```
2. Navigate to the folder:
   ```sh
   cd LAB-2-MonoAlphabetic-Cipher
   ```
3. Run the script:
   ```sh
   python monoalphabetic_cipher.py
   ```

## License
This project is licensed under the MIT License.

