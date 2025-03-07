# DES Cipher Implementation

This repository contains an implementation of the **Data Encryption Standard (DES)** cipher in Python, located in:

```
INS LAB/Lab_6/DES.py
```

## 📜 About DES
The **Data Encryption Standard (DES)** is a symmetric-key block cipher that encrypts data in **64-bit blocks** using a **56-bit key**. It follows a Feistel network structure and operates through **16 rounds of encryption**.

## 🛠 Features
- Encrypts and decrypts messages using the DES algorithm.
- Supports key expansion and round transformations.
- Implements permutation and substitution steps as per the DES standard.

## 🚀 Usage
### Running the DES Implementation
Make sure you have Python installed, then navigate to the directory containing `DES.py` and run:

```sh
python DES.py
```

### Running in GitHub Workspace
To run this code in **GitHub Codespaces or GitHub Actions**, follow these steps:

1. Open the repository in **GitHub Codespaces**.
2. Ensure Python is installed by running:
   ```sh
   python --version
   ```
3. Navigate to the `Lab_6` directory:
   ```sh
   cd INS\ LAB/Lab_6
   ```
4. Run the script:
   ```sh
   python DES.py
   ```
5. Follow the prompts for input.

### Example Input/Output
```plaintext
Enter plaintext: HELLO123
Enter key: SECRETK
Ciphertext: 0xA1B2C3D4...
Decrypted text: HELLO123
```

## 📂 Folder Structure
```
INS LAB/
│── Lab_6/
│   ├── DES.py  # Python implementation of DES cipher
│   ├── README.md  # Documentation (this file)
```

## 🧩 How It Works
1. **Initial Permutation (IP)**: Reorders the plaintext bits.
2. **16 Feistel Rounds**: Uses substitution and permutation to encrypt data.
3. **Final Permutation (FP)**: Produces the ciphertext.
4. **Decryption**: Same process in reverse.

## 📝 Notes
- DES is considered **insecure** due to its short key length (56-bit).
- It has been replaced by **AES (Advanced Encryption Standard)** in modern cryptography.

## 🏆 Acknowledgments
This implementation follows the standard DES encryption process for educational purposes.

---
📌 **For improvements, feel free to modify and contribute!** 🚀

