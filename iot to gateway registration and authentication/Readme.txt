idN : identity of IOT node
Vg : Public key of gateway
Lx : Shared Symmetric session key
Idg : Identity of gateway
Ru : Shared Random Tuple
Rx : Shared Random Tuple
HN : hash digest Tuple h(IDn||Rn)
RN:  Shared Random Tuple encrypted and then retrieved using decrytion on other node

MN : hash digest Tuple h(HN||RN||RGn) 

functions used:
EccMultiply(GenPoint,ScalarHex):
A function used for ECC based multiplication of doubling and addition

gen_public_key(self):
A function used for computing ECC based Public key

ECadd(a,b):
A function used for ECC addition

ECdouble(a): 
A function used for ECC doubling