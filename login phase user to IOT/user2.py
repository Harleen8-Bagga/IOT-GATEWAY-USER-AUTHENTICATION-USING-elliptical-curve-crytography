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
		print('THE PRIVATE KEY')
		#print(self.__a)
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
d= DiffieHellman()      
print("Idu",idA)
Private_key=d.get_private_key()
print("Private Key=",Private_key) 
(PKax,PKay)=(d.gen_public_key())
PK=(int(PKax),int(PKay))
print("Public key=",PK) 
stringca=idA+str(PKax)+str(PKay)
md5a=md5()
md5a.update(stringca.encode('utf-8'))
ca=md5a.hexdigest()

M1=idA+','+str(PKax)+','+str(PKay) #M1 is Ca



print("Ca=","(",M1,")")

   
stringca=idA+str(PKax)+str(PKay)
md5a=md5()
md5a.update(stringca.encode('utf-8'))
ca=md5a.hexdigest()

M1=idA+','+str(PKax)+','+str(PKay) #M1 is Ca



print("Ca=","(",M1,")")

   





Idu=idA
PWu='0123456892341569'
Bu='0007890'
    
 # TCP connection to responder B
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setblocking(1)
print('begin connection')
sock.connect((server_ip, server_port))
try:
   while (token==0):
       print('connection up')
       print ('connected')
       sock.send(Idu.encode('utf-8'))
       sock.send(PWu.encode('utf-8'))
       sock.send(Bu.encode('utf-8'))
       token=1
            

       
      
except KeyboardInterrupt:
        s.close()
        print("KeyboardInterrupt")
    #sys.exit(0)
    



     
