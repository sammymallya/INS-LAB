# LAB-1: Caesar Cipher

## Overview
This repository contains an implementation of the **Caesar Cipher**, a classical encryption technique that shifts each letter in the plaintext by a fixed number of positions in the alphabet.

## Features
- Encrypts and decrypts text using the Caesar Cipher algorithm.
- Supports custom shift values.
- Works with uppercase and lowercase letters.
- Ignores non-alphabetic characters.

## Usage
### Encryption
Run the script and input the plaintext along with the shift value to obtain the encrypted text.

### Decryption
Provide the ciphertext and shift value to retrieve the original message.

## Code Structure
- `caesar_cipher.py` - Contains the implementation of the Caesar Cipher.
- `README.md` - Documentation for the project.

## Example
```python
# Example usage
plaintext = "HELLO WORLD"
shift = 3
ciphertext = encrypt(plaintext, shift)
print("Encrypted:", ciphertext)
```

## Requirements
- Python 3.x

## How to Run
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/LAB-1-Caesar-Cipher.git
   ```
2. Navigate to the folder:
   ```sh
   cd LAB-1-Caesar-Cipher
   ```
3. Run the script:
   ```sh
   python caesar_cipher.py
   ```

## License
This project is licensed under the MIT License.

