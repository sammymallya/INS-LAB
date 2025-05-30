#Vignere cipher
def encrypt_v(p, k):
    k = k.upper()
    ciphertext = ""
    k_index = 0
    for char in p.upper():
        if char.isalpha():
            shift = ord(k[k_index]) - ord('A')
            ciphertext += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            k_index = (k_index + 1) % len(k)
        else:
            ciphertext += char
    return ciphertext

def decrypt_v(p, k):
    k = k.upper()
    ciphertext = ""
    k_index = 0
    for char in p.upper():
        if char.isalpha():
            shift = ord(k[k_index]) - ord('A')
            ciphertext += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
            k_index = (k_index + 1) % len(k)
        else:
            ciphertext += char
    return ciphertext

p=input("Enter plaintext:")
k=input("enter key:")
n=encrypt_v(p,k)
c=decrypt_v(n,k)
print("Encrypted:",n)
print("decrypted:",c)
