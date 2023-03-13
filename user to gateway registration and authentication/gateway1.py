# -*- coding: utf-8 -*-
"""
Created on Tue May 11 10:16:10 2021

@author: Harleen
"""

import os
import binascii
import hashlib
import socket
#from IOTSocket import IOTSocketClient as sock
import time
from clrprint import *
import random
import hashlib
import sys
import shutil
from subprocess import call
#from secret_code import SKa, refresh
from hashlib import sha256,md5
from Crypto.Cipher import AES


host = '127.0.0.0'
port = 9000

#server_ip = '192.168.137.225'
#server_port = 6633
#idA='00000001'
idB='00000002'
token=0
Pcurve = 2**256-2**224 + 2**192 + 2**96 - 1
Acurve=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
Bcurve=0xAC6535D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

Gx = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFF
Gy = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B3943

GPoint = (int(Gx),int(Gy))#Generator point


N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field


privKey=0x87DF38D61239141838E40034E905446A35497A8ADEA8B7D5241A1E7F2C95A04D

def modinv(a,n=Pcurve): 		#'division' in elliptic curves
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        ratio = high/low
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECadd(a,b): 			# EC Addition
    LamAdd = ((b[1]-a[1]) * modinv(b[0]-a[0],Pcurve)) % Pcurve
    x = (LamAdd*LamAdd-a[0]-b[0]) % Pcurve
    y = (LamAdd*(a[0]-x)-a[1]) % Pcurve
    return (x,y)

def ECdouble(a): 			# EC Doubling
    Lam = ((3*a[0]*a[0]+Acurve) * modinv((2*a[1]),Pcurve)) % Pcurve
    x = (Lam*Lam-2*a[0]) % Pcurve
    y = (Lam*(a[0]-x)-a[1]) % Pcurve
    return (x,y)

def EccMultiply(GenPoint,ScalarHex): 	# Doubling & Addition
    if ScalarHex == 0 or ScalarHex >= N: raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(ScalarHex))[2:]
    Q=GenPoint
    for i in range (1, len(ScalarBin)):
        Q=ECdouble(Q); 
        if ScalarBin[i] == "1":
            Q=ECadd(Q,GenPoint);
    return (Q)
class DiffieHellman:    
       
   def __init__(self, group=14):
	   self.__a = int(binascii.hexlify(os.urandom(32)), base=16)
   def get_private_key(self):
	   """ Return the private key (a) """
	   print('THE PRIVATE KEY')
	   print(self.__a)
	   return self.__a

   def gen_public_key(self):
	   """ Return A, A = g ^ a mod p """
	# calculate G^a mod p
	   print('THE PUBLIC KEY')
		#print(EccMultiply(GPoint,self.__a))
	   return EccMultiply(GPoint,self.__a)

   def check_other_public_key(self, x,y):
		# check if the other public key is valid based on NIST SP800-56
		# 2 <= g^b <= p-2 and Lagrange for safe primes (g^bq)=1, q=(p-1)/2

		#if 2 <= other_contribution and other_contribution <= int(KDF.N) - 2:
			
           if (x < 0 or x >= N or y < 0 or y > N):
               return False
           if not self:
               return False
           return True
   def gen_shared_key(self, PR):
       f.shared_key = EccMultiply(PR,self.__a)
       return hashlib.sha256(str(self.shared_key).encode()).hexdigest() 
	     
       




	
           
d=DiffieHellman()   


print("IDg= \n",idB)
Private_key=d.get_private_key()
print(Private_key) 
(PKbx,PKby)=(d.gen_public_key())
PKb=(int(PKbx),int(PKby))
print(PKb)#Print public key
r=random.randint(10000000,999999999)
#f = open('storageB.txt', 'r')
#sk = f.read()
#skList = sk.split(',')
#stup =refresh(skList[0],skList[1])
#Rn = int(skList[0])
#Ln = int(skList[1])

#print ("skList\n",skList)
#print ("Rn\n",Rn)
#print ("Ln\n",Ln)
#print ("Rn + Ln\n",Rn+Ln)
Ra=random.randint(10000000,999999999)
#Ub1=Ra+Rn
#b = Ub1 + Ln
stringcb=idB+str(PKbx)+str(PKby)
md5b=md5()
md5b.update(stringcb.encode('utf-8'))
cb=md5b.hexdigest()

M2=idB+','+str(int(PKbx))+','+str(int(PKby))+','+cb
print("Cb=",M2)


#with open('storageA.txt','w')as f:
    #f.write(str(Rn)+","+str(Ln))
 # TCP connection to responder B
print('Begin')

    #TCP link
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
Tuple=('127.0.0.1',9000)
sock.bind(Tuple)

print('Listen to the connection from client...')
sock.listen(5)
try:
    while (token==0):
        connection, address = sock.accept()
        print('Connected. Got connection from ', address)
        M2=idB+','+str(int(PKbx))+','+str(int(PKby))+','+cb
        #print(M2)
        connection.send(M2.encode('utf-8'))
         # 2.Gateway side: 1)receive Ia from A 2)Retrieve Ca from  2)compute cb 3)send M2
        idA1 =connection.recv(1024)
        print("Idu recieved=",idA1)
        M1=connection.recv(1024)
        #ca_check=M1.hexadigest()
        U4=str(M1)
        print("Recieved  CAu =",M1)
        idA = U4.split(',')[0]+"'"
        print("recieved Idu from CAu= ",idA)
        #PKax = U4.split(',')[1]
        #PKay = U4.split(',')[2]
        #cb = U3.split(',')[3]
        #PKa = (PKax,PKay)# This is Vg public address of gateway
        
            #Decryt the recived encrypted key
          #msg2=cipher.decrypt(msg)
        #Ru=msg2[0]
        #idA1=msg2[1]
        #R1=msg2[2]
        #K=EccMultiply(R1,Private_key)
        #Kx=K[0]
        #Ky=K[1]    
            
        #key=Kx  
        # Integrity check
        #print(str(idA))
        #print(str(idA1))
        
        if str(idA1) == str(idA):
           #print("Recieved Vu= ",PKa)#Vu recovered from CAu
           R1=connection.recv(1024)
           msg=connection.recv(1024)
           rgu=random.randint(10,99)
           Rgu=EccMultiply(GPoint,rgu)
           idA='00000001'
           #print(msg1)
           #Ru=msg1[0]
           #idA1=msg1[1]
           K=EccMultiply(R1,Private_key)
           #print("Computed key K =",K)
           Kx=int(K[0])
           print("Computed Symmetric session key Kx=",str(R1))
           Ky=K[1]
           cipher = AES.new(Kx.to_bytes(32,'big'), AES.MODE_ECB)
           msg1 =cipher.decrypt(msg)
           
           #msg2=msg1.decode('utf-8')
           Mu=connection.recv(1024)
           with open('storageC.txt','w')as f:
                 f.write(str(idA)+","+str(Mu))
           print("------------------------------------------")
           print("IDu and recieved encrypted key Mu sent to staorageA")      
           
           
           
           print("Decrypted Idu =",idA1)
           
           print("Verification status:Verification sucessful,decrypted Idu=recieved Idu & decrypted R1=recieved R1\n")  
           print("-----------------------------------------------------")
           print("Communicated Idu=",idA1)
           print("Verification status: Recieved IDu = communicated IDu Registration process of user complete") 
        token =1     
            #Concatenated_text=sha256(Ru+RGu)     
            #cipher = AES.new(key, AES.MODE_ECB)
            #msg =cipher.encrypt(Concatenated_text) 
            #connection.send(idB,msg) 
        #else:
           #print('verification failed')
           
except KeyboardInterrupt:
        s.close()
        print("KeyboardInterrupt")            
             
         
        
