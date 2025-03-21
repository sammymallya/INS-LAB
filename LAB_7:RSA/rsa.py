def gcd(a,b):
    while b:
        a,b = b,a%b
    return a
p = int(input("enter a number: "))
q = int(input("enter a number: "))
n = p*q
phi = (p-1)*(q-1)
for i in range(2,phi):
    if(gcd(i,phi)==1):
        e = i
        break
for k in range(100):
    d = ((phi*k)+1)/e
    if(d%1 == 0.0):
        d=int(d)
        break
print(f"Public Key:<{e},{n}>")
print(f"Private Key:<{d},{n}>")
msg = int(input("Enter a msg: "))
c=(msg**e)%n
print("Cipher: ",c)
d=(c**d)%n
print("Decrypt: ",d)
