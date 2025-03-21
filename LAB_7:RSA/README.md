# RSA Implementation - LAB 7 (INS-LAB)

This repository contains an implementation of the **RSA algorithm**, a widely used public-key cryptosystem for secure data encryption and decryption. 

## 📌 About RSA
The **Rivest-Shamir-Adleman (RSA)** algorithm is based on the mathematical difficulty of factoring large prime numbers. It is used for secure data transmission and is a fundamental part of modern cryptography.

### How RSA Works:
1. **Key Generation:** Select two large prime numbers and compute their product (modulus).
2. **Public Key:** Generated using an encryption exponent.
3. **Private Key:** Generated using a decryption exponent.
4. **Encryption:** Uses the public key to convert plaintext into ciphertext.
5. **Decryption:** Uses the private key to retrieve the original plaintext.

---

## 🚀 Running `rsa.py` in GitHub Codespaces

To execute the **RSA implementation** in GitHub Codespaces, follow these steps:

### **1️⃣ Open Codespaces**
- Navigate to the **INS-LAB/LAB_7** repository on GitHub.
- Click on the **“<> Code”** button.
- Select **“Codespaces”** and create a new Codespace environment.

### **2️⃣ Install Dependencies (if any)**
- Open the terminal in Codespaces.
- Run the following command to ensure Python is installed:
  ```sh
  python3 --version
If Python is not available, install it using:
sudo apt update && sudo apt install python3
3️⃣ Run the RSA Script
Navigate to the LAB_7/RSA directory:
sh
Copy
Edit
cd INS-LAB/LAB_7/RSA
Execute the script:
sh
Copy
Edit
python3 rsa.py
4️⃣ Expected Output
The script will generate RSA key pairs.
It will demonstrate encryption and decryption of a sample message.
🛠 Features of This Implementation
✔ Key generation using prime numbers
✔ Encryption & decryption of messages
✔ Mathematical explanation of RSA within comments
✔ Easy to modify and extend for learning purposes

📜 License
This project is for educational purposes and follows an open-source license. Feel free to modify and enhance it.

✨ Contributions
Contributions are welcome! If you’d like to improve the implementation, open a pull request with detailed explanations of your changes.

📞 Contact
For any questions, reach out via GitHub Issues or email: your-email@example.com

🎯 Happy coding & secure encryption with RSA! 🚀🔐
