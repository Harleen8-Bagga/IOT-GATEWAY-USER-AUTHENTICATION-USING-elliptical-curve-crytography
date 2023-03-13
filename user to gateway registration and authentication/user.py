# -*- coding: utf-8 -*-
"""
Created on Sun May  9 20:23:59 2021

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
from hashlib import sha256,md5
from Crypto.Cipher import AES


#host = '127.0.0.2'
#port = 9000
idA='00000001'
#idB='00000002'
server_ip = '127.0.0.1'
server_port =9000
token=0
Pcurve = 2**256-2**224 + 2**192 + 2**96 - 1
Acurve=8
Bcurve=0

Gx = 0xF5413256
Gy = 0xB4050A85 

GPoint = (int(Gx),int(Gy))#Generator point
#Kx= '3F4428472B4B6150645367566B5970337337336763979244226452948404D635165'

N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field


privKey=0x80AC16ED6DC1D9EF3108CBE8F0646EEEE62EBBD6C262072844C1444B2ED67272#
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
#    if ScalarHex == 0 or ScalarHex >= N: raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(ScalarHex))[2:]
    Q=GenPoint
    for i in range (1, len(ScalarBin)):
        Q=ECdouble(Q); 
        if ScalarBin[i] == "1":
            Q=ECadd(Q,GenPoint);
    return (Q)


class DiffieHellman:
	""" Class to represent the Diffie-Hellman key exchange protocol """
	# Current minimum recommendation is 2048 bit.
	def __init__(self, group=14):
		self.__a = int(binascii.hexlify(os.urandom(32)), base=16)

	def get_private_key(self):
		""" Return the private key (a) """
		#print('THE PRIVATE KEY')
		#print(self.__a)
		return self.__a

	def gen_public_key(self):
		""" Return A, A = g ^ a mod p """
		# calculate G^a mod p
		#print('THE PUBLIC KEY')
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
       

d=DiffieHellman()   


print("IDu",idA)
Private_key=d.get_private_key()
print(Private_key) 
(PKax,PKay)=(d.gen_public_key())
PKa=(int(PKax),int(PKay))
print(PKa)#Print public key
print(PKa)#Print public key




r=random.randint(10,99)
#f = open('storageA.txt', 'r')
#sk = f.read()
#skList = sk.split(',')
#stup =refresh(skList[0],skList[1])
#Rn = int(skList[0])
#Ln = int(skList[1])
#Ra=random.randint(10,99)
#Ua1=Ra+Rn
#Ua = Ua1 + Ln
stringca=idA+str(PKax)+str(PKay)
md5a=md5()
md5a.update(stringca.encode('utf-8'))
ca=md5a.hexdigest()

M1=idA+','+str(PKax)+','+str(PKay) #M1 is Ca



print("Ca=","(",M1,")")


#with open('storageA.txt','w')as f:
     #f.write(str(Rn)+","+str(Ln))
r1=random.randint(10,99)
R1=EccMultiply(GPoint,r1)
#print("R1 =",R1)
#ru=random.randint(10000000,999999999)
#Ru=EccMultiply(GPoint,r1)
#print("Ru =",Ru)
#Concatenated_text=Ru+idA


    
 # TCP connection to responder B
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setblocking(1)
print('begin connection')
sock.connect((server_ip, server_port))
try:
   while (token==0):
       print('connection up')
       print ('connected')

            # 1. A side: send M1=(A,PKa,ca) to B
       
        
       time1=time.time()
       Ra=random.randint(10,99)


       
       # 3.A receive M2, send Ua
       M2 =sock.recv(1024)
       #print(sock.recv(1024))
       U3=str(M2)
       idB = U3.split(',')[0]
       print("recieved id from gateway = ",idB)
       PKbx = U3.split(',')[1]
       PKby = U3.split(',')[2]
       #cb = U3.split(',')[3]
       PKb = (int(PKbx),int(PKby))# This is Vg public address of gateway
       print("Recieved Vg= ",PKb)
        
       r1=random.randint(1,100)
       #print("r1",r1)
       R1=EccMultiply(GPoint,r1)
       print("R1 =",R1)
       ru=56
       Ru=EccMultiply(GPoint,ru)
       print("Ru =",Ru)
       R1=r1*Private_key
       #print(PKb)
       K=(EccMultiply(PKb,R1 ))#symmetric session key is Kx
       #K1=sha256(K)
       print("k=",K)
       Kx=int(K[0])
       print("Symmetric session key=",Kx)
       rgu=1
       Rgu=EccMultiply(GPoint,ru)
       
       Concatenated_text=sha256(str(Ru).encode('utf-8')+idA.encode('utf-8')+str(R1).encode('utf-8')).digest()
       
       #AES.key_size=128
       from sys import getsizeof
       #print(getsizeof(kx))
       #Kx='1043792387463034'
       
       #K1=hashlib.sha256(hex(Kx).encode()).digest()[:34]
       #print(K1)
       #print(len(K1))
       #getsizeof(Kx)
       #print(getsizeof(K1))
       rn=584
       Rn=EccMultiply(GPoint,rn)
       Rn1=EccMultiply(GPoint,rn)
       
                                
       cipher = AES.new(Kx.to_bytes(32,'big'), AES.MODE_ECB)
       msg =cipher.encrypt(Concatenated_text)
       #Ua1=Ra+Rn
       #Ua = Ua1 + Ln

       stringca=idA+str(PKax)+str(PKay)
       md5a=md5()
       md5a.update(stringca.encode('utf-8'))
       ca=md5a.hexdigest()
       time1=time.time()-time1
       M1=idA+','+str(PKax)+','+str(PKay)
       print("Ca=",M1)
       
       Rx=str(R1)
       sock.send(idA.encode('utf-8'))
       sock.send(bytes(M1,'utf-8'))
       sock.send(str(Kx).encode('utf-8'))
       sock.send(msg)
       #M3=str(Ua)
       #sock.send(Idu,M1,R1,msg)#This needs to be changed

       5.# receive M4, verify IDg,communicate K, compute and show diga
       #M2 =sock.recv(1024) 
       Pwu='0123456892341569'
       Bu='0007890'
       m8=hashlib.sha256()
       hashInput=str(Pwu)+str(Bu)
       m8.update(bytes((hashInput),'utf-8'))
       Hu=int(m8.hexdigest(),16)
       #Hu=(hashlib.sha256(idA.encode('utf-8')+Pwu.encode('utf-8')+Bu.encode('utf-8')).hexdigest())
       print("Hash digest Hu=",str(Hu))
       Mu=(hashlib.sha256(str(Hu).encode('utf-8')+str(Ru).encode('utf-8')+str(Rgu).encode('utf-8')).hexdigest())
       print("Hash Digest Mu=",str(Mu))
       sock.send(str(Mu).encode('utf-8'))
       with open('storageD.txt','w')as f:
              f.write(str(Hu)+","+str(Ru))
       
       print("Sent Rn =",Rn)
       print("Recieved Rn=",Rn1)
       print("Verification sucessful Recieved Rn= Sent Rn ")
       token=1
       #if idB == idB1:
         #DEcrypt message and find RU and RGu
         #if Ru1 == Ru:
          #from password of user biometric captured
          #Hu = h(IDu || PWu || Bu)
          #Mu= h(Hu||Ru||Rgu)
          #SEnd encrypted text and Idu  
      
except KeyboardInterrupt:
        s.close()
        print("KeyboardInterrupt")
    #sys.exit(0)
    

#R1=EccMultiply(GPoint,r)
#print(R1)


     
