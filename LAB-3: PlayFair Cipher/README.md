# LAB-3: Playfair Cipher

## Overview
This repository contains an implementation of the **Playfair Cipher**, a digraph substitution cipher that encrypts pairs of letters using a 5x5 matrix.

## Features
- Encrypts and decrypts text using the Playfair Cipher algorithm.
- Supports custom key phrases to generate the 5x5 matrix.
- Handles digraphs and repeated letters effectively.
- Works with uppercase and lowercase letters.

## Usage
### Encryption
Run the script and input the plaintext along with the key phrase to generate the encrypted text.

### Decryption
Provide the ciphertext and key phrase to retrieve the original message.

## Code Structure
- `playfair_cipher.py` - Contains the implementation of the Playfair Cipher.
- `README.md` - Documentation for the project.

## Example
```python
# Example usage
plaintext = "HELLO WORLD"
key_phrase = "SECRET"
ciphertext = encrypt(plaintext, key_phrase)
print("Encrypted:", ciphertext)
```

## Requirements
- Python 3.x

## How to Run
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/LAB-3-Playfair-Cipher.git
   ```
2. Navigate to the folder:
   ```sh
   cd LAB-3-Playfair-Cipher
   ```
3. Run the script:
   ```sh
   python playfair_cipher.py
   ```

## License
This project is licensed under the MIT License.
