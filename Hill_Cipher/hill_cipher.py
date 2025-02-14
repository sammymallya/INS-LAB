import numpy as np

def text_to_number(plaintext, key_matrix_size):
    # Pad plaintext to fit the matrix size
    while len(plaintext) % key_matrix_size != 0:
        plaintext += 'X'

    # Convert text to numerical values
    plaintext_vector = [ord(char) - ord('A') for char in plaintext]
    return plaintext_vector

def hill_cipher_encrypt(plaintext, key_matrix):
    n = len(key_matrix)  # Matrix size
    plaintext_vector = text_to_number(plaintext, n)
    ciphertext = ""

    for i in range(0, len(plaintext_vector), n):
        block = plaintext_vector[i:i + n]
        result = np.dot(key_matrix, block).astype(int) % 26  # Ensure integer output
        ciphertext += "".join(chr(num + ord('A')) for num in result)

    return ciphertext

def is_invertible_mod_26(matrix):
    det = int(round(np.linalg.det(matrix)))  # Get determinant as integer
    det_mod_26 = det % 26
    try:
        inv_det = pow(det_mod_26, -1, 26)  # Modular inverse
        return True
    except ValueError:
        return False

# Get user input
plaintext = input("Enter plaintext: ").upper()

try:
    matrix_size = int(input("Enter the matrix size: "))
    print("Enter the key matrix row-wise:")

    key_matrix = []
    for i in range(matrix_size):
        row = list(map(int, input().split()))
        if len(row) != matrix_size:
            raise ValueError("Row length does not match matrix size.")
        key_matrix.append(row)

    key_matrix = np.array(key_matrix)

    # Check if key matrix is invertible mod 26
    if not is_invertible_mod_26(key_matrix):
        raise ValueError("Key matrix is not invertible modulo 26. Choose a different matrix.")

    ciphertext = hill_cipher_encrypt(plaintext, key_matrix)
    print("Ciphertext:", ciphertext)

except ValueError as e:
    print("Invalid input:", e)
