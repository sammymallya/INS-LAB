#encryption
def encrypt (text,s1):
    output=""
    for char in text:
        if 'A'<= char <='Z':
            p=ord(char)-ord('A')
            c=(p+s1)%26
            output+=chr(c+ord('A'))
        else:
            output+=char
    return output

ptext=input("enter text(in uppercase):")
s1=int(input("enter shift:"))
print("text:"+ptext)
print("shift:"+str(s1))
print("ciphertext:"+encrypt(ptext,s1))

#decryption
def decrypt(ctext,s1):
    output=""
    for char in ctext:
        if 'A' <= char <='Z':
            p=ord(char)-ord('A')
            c=(p-s1)%26
            output+=chr(c+ord('A'))
    return output

enc_text=encrypt(ptext,s1)
dec_text=decrypt(enc_text,s1)
print("decrypted text:"+dec_text)
