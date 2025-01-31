import numpy as np

# for playfair cipher
key = np.full((5, 5), "S")
print(key)

# function to create key matrix from user input
def createKey(key):
    for i in range(0, 5):
        for j in range(0, 5):
            key[i][j] = input("enter alphabets for key:").upper()
    print("Key matrix formed is: ")
    print(key)

# inputting plaintext from user and replacing J by I, and splitting it into digraphs
def input_plaintext():
    plaintext = input("enter plaintext: ")
    plaintext = plaintext.upper()
    print(plaintext)
    while "I" in plaintext:
        plaintext = list(plaintext)
        x = -1
        x = plaintext.index("I")
        if x != -1:
            plaintext[x] = "J"
    plaintext = ''.join(plaintext)
    return plaintext

# function to find position of letter in key matrix
def find_position(letter, key):
    for i in range(5):
        for j in range(5):
            if key[i][j] == letter:
                return i, j
    return None, None

# function to encrypt plaintext using playfair cipher
def encrypt(plaintext, key):
    ciphertext = ""
    copy = list(plaintext)
    i = 0
    while i < len(copy):
        a = copy[i]
        b = copy[i + 1] if i + 1 < len(copy) else 'X'  # if single letter remains, pad with X
        if a == b:
            b = 'X'  # rule to avoid double letters in pair
        r1, c1 = find_position(a, key)
        r2, c2 = find_position(b, key)
        if r1 == r2:  # same row case
            ciphertext += key[r1][(c1 + 1) % 5] + key[r2][(c2 + 1) % 5]
        elif c1 == c2:  # same column case
            ciphertext += key[(r1 + 1) % 5][c1] + key[(r2 + 1) % 5][c2]
        else:  # rectangle swap case
            ciphertext += key[r1][c2] + key[r2][c1]
        i += 2  # move to next digraph
    return ciphertext

# function to decrypt ciphertext using playfair cipher
def decrypt(ciphertext, key):
    plaintext = ""
    copy = list(ciphertext)
    i = 0
    while i < len(copy):
        a = copy[i]
        b = copy[i + 1] if i + 1 < len(copy) else 'X'  # if single letter remains, pad with X
        r1, c1 = find_position(a, key)
        r2, c2 = find_position(b, key)
        if r1 == r2:  # same row case
            plaintext += key[r1][(c1 - 1) % 5] + key[r2][(c2 - 1) % 5]
        elif c1 == c2:  # same column case
            plaintext += key[(r1 - 1) % 5][c1] + key[(r2 - 1) % 5][c2]
        else:  # rectangle swap case
            plaintext += key[r1][c2] + key[r2][c1]
        i += 2  # move to next digraph
    return plaintext

# taking user inputs for key matrix and plaintext
createKey(key)
plaintext = input_plaintext()

# encryption process
ciphertext = encrypt(plaintext, key)
print("Ciphertext: ", ciphertext)

# decryption process
decrypted_text = decrypt(ciphertext, key)
print("Decrypted Text: ", decrypted_text)

