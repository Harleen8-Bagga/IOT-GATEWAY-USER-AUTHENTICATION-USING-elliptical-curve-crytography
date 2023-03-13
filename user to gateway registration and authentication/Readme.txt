IDg : identity of gateway
Cb : Public key certificate based on ECC of  gateway
CAu :Public key certificate based on ECC of  user
IDu :identity of user 
Kx  : Symmetric session key
PWu:password of user U
Bu:Biometric of user U
HU:Hash digest h(PWu||Bu||IDu)
Ru :Exchanged Random tuple
Rgu :Exchanged Random tuple
MU :Hash digest h(HU||RU||Rgu)

functions used:
EccMultiply(GenPoint,ScalarHex):
A function used for ECC based multiplication of doubling and addition

gen_public_key(self):
A function used for computing ECC based Public key

ECadd(a,b):
A function used for ECC addition

ECdouble(a): 
A function used for ECC doubling

modinv(a,n=Pcurve):
For division of elliptic curves
