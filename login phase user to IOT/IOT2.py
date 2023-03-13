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
idN='00000003'
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
		print('THE PRIVATE KEY')
		#print(self.__a)
		return self.__a

	def gen_public_key(self):
		""" Return A, A = g ^ a mod p """
		# calculate G^a mod p
		print('THE PUBLIC KEY')
		#print(EccMultiply(GPoint,self.__a))
		return EccMultiply(GPoint,self.__a)

d=DiffieHellman()	
print("idN",idN)
Private_key=d.get_private_key()
print("Private Key=",Private_key) 
(PKax,PKay)=(d.gen_public_key())
PK=(int(PKax),int(PKay))
print("Public key=",PK)




    
 # TCP connection to responder B
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

sock.bind(('127.0.0.1',9000))

print('Listen to the connection from client...')
sock.listen(5)
try:
   while (token==0):
       connection, address = sock.accept()
       print('Connected. Got connection from ', address)
       count =0
       while (count<=5):
         Idu=connection.recv(1024)
         PWu=connection.recv(1024)
         Bu=connection.recv(1024)
         m8=hashlib.sha256()
         m8.update((Idu+PWu+Bu))
         HU1=int(m8.hexdigest(),16)
         H1=HU1
         print("H1 =",HU1)
         #print("HU1 =",int(HU1.hexdigest(),16))
         f= open('storageD.txt')
         sk=f.read()
         skList=sk.split(',')
         HU=skList[1]
         print("HU = ",str(H1))
         
         if str(HU1) == str(H1):
            print("Since both the hash digests Match so valid user")
            break
         else:
              print("Invalid user trying to acess")
         count=count+1
       token=1  
                 
       
        
       
       
       
       
           
             
               
       
       
        
      
except KeyboardInterrupt:
        s.close()
        print("KeyboardInterrupt")
    #sys.exit(0)
    


     
