# LAB-4: Hill Cipher

## Overview
This repository contains an implementation of the **Hill Cipher**, a polygraphic substitution cipher that uses matrix multiplication for encryption and decryption.

## Features
- Encrypts and decrypts text using the Hill Cipher algorithm.
- Supports custom key matrices for encryption.
- Works with uppercase and lowercase letters.
- Handles input padding for non-square matrices.

## Usage
### Encryption
Run the script and input the plaintext along with the key matrix to generate the encrypted text.

### Decryption
Provide the ciphertext and key matrix to retrieve the original message.

## Code Structure
- `hill_cipher.py` - Contains the implementation of the Hill Cipher.
- `README.md` - Documentation for the project.

## Example
```python
# Example usage
plaintext = "HELLO"
key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
ciphertext = encrypt(plaintext, key_matrix)
print("Encrypted:", ciphertext)
```

## Requirements
- Python 3.x
- NumPy library for matrix operations

## How to Run
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/LAB-4-Hill-Cipher.git
   ```
2. Navigate to the folder:
   ```sh
   cd LAB-4-Hill-Cipher
   ```
3. Install dependencies:
   ```sh
   pip install numpy
   ```
4. Run the script:
   ```sh
   python hill_cipher.py
   ```

## License
This project is licensed under the MIT License.

