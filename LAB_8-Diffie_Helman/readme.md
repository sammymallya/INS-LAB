# Diffie-Hellman Key Exchange Implementation in Python

This repository contains a Python implementation of the Diffie-Hellman key exchange algorithm.  Diffie-Hellman is a method for securely exchanging cryptographic keys over a public channel.  This code is located in `LAB_8-Diffie_Helman/diffie.py`.

## Diffie-Hellman Key Exchange Explained

The Diffie-Hellman key exchange algorithm allows two parties to establish a shared secret over an insecure channel. Here's how it works:

1.  **Public Parameters:** Two public values, a prime number `p` and a generator `g` (where `g` is a primitive root modulo `p`), are agreed upon by both parties.
2.  **Private Keys:** Each party (let's call them Alice and Bob) independently chooses a secret private key (`a` for Alice, `b` for Bob).
3.  **Public Key Calculation:**
    * Alice calculates her public key: `A = (g^a) mod p`
    * Bob calculates his public key: `B = (g^b) mod p`
4.  **Public Key Exchange:** Alice and Bob exchange their public keys, `A` and `B`.
5.  **Shared Secret Calculation:**
    * Alice computes the shared secret: `s = (B^a) mod p`
    * Bob computes the shared secret: `s = (A^b) mod p`
6.  **Result:** Both Alice and Bob arrive at the same shared secret `s`, which can then be used for symmetric encryption.

## How to Run the Python Code

You can run the Python code in `LAB_8-Diffie_Helman/diffie.py` using either GitHub Codespaces or Google Colab.

### Running in GitHub Codespaces

1.  **Open the repository:** Open your GitHub repository in your browser.
2.  **Create a codespace:** Click the "Code" button, and then click "Create codespace on main".  This will open a VS Code environment in your browser.
3.  **Navigate to the directory:** In the VS Code terminal, navigate to the directory containing the script:
    ```bash
    cd LAB_8-Diffie_Helman
    ```
4.  **Run the script:** Execute the Python script:
    ```bash
    python diffie.py
    ```

### Running in Google Colab

1.  **Open Colab:** Go to [colab.research.google.com](colab.research.google.com) and create a new notebook.
2.  **Upload the file:**
    * You can upload the `diffie.py` file directly.
    * Alternatively, if the file is in a GitHub repository, you can clone the repository:
        ```python
        !git clone <your_repository_url>
        %cd <your_repository_name>/LAB_8-Diffie_Helman
        ```
3.  **Run the code:** Execute the Python code:
    ```python
    !python diffie.py
    ```
    or
    ```python
    import subprocess
    subprocess.run(['python', 'diffie.py'])
    ```
