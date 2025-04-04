p=int(input("prime no.: "))
a=int(input("premitive root: "))

PvA=int(input("PvA:"))
PvB=int(input("PvB:"))

PbA=pow(a,PvA,p)
PbB=pow(a,PvB,p)

print("Public Key of A: ",PbA)
print("Public Key of B: ",PbB)

ShA=pow(PbB,PvA,p)
ShB=pow(PbA,PvB,p)

print("shared key of A: ",ShA)
print("Shared key of B: ",ShB)
if(ShA==ShB):
    print("Shared key is the same. Key exchange is succesful...")
else:
    print("Shared is not the same....")
