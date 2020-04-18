#!/usr/bin/env python3
#Chinese Reminders Theroem application for RSA decryption 
#From China With Love :)

#Equations are supposed to be like "x is congruent to c mod n"
#Link with RSA encryption : a ciphertext C is congruent to M^e mod N (with M = plaintext and e = public exponent)

import argparse
import base64
import gmpy
import libnum
import functools
from oscrypto import keys, asymmetric, _openssl


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("--integers",help="Integer mode : use integers as direct inputs",action="store_true")
group.add_argument("--files",help="File mode : modulus as PEM encoded RSA public keys and messages as base64",action="store_true")
parser.add_argument("-n",help="Modulus value(s) or public key files. Use space as separator",nargs='*',required=True)
parser.add_argument("-c",help="Value(s) of congruences or encrypted messages, in same order as the modulus value(s)",nargs='*',required=True)
args = parser.parse_args()

def parse_der_pubkey(pem_or_der_pubkey):
	return asymmetric.load_public_key(keys.parse_public(pem_or_der_pubkey))

def extract_pubkeyInfo(cert):
	if isinstance(cert,_openssl.asymmetric.PublicKey):
		pubkey = cert.unwrap()
	elif isinstance(cert,_openssl.asymmetric.Certificate):
		pubkey = cert.public_key.unwrap()
	else:
		print("Certificate or public key type unknown")
		exit()

	if (type(pubkey).__name__ == "RSAPublicKey"):
		N = int(pubkey["modulus"].native)
		E = int(pubkey["public_exponent"].native)
		return N,E
	else:
		print("Certficate or public key does not use RSA")
		exit()

def read_message_from_file(file_message_path):
	try:
		file_message = open(file_message_path,'rb')
		return int.from_bytes(base64.b64decode(file_message.read()),byteorder='big')
	except Exception as e:
		print("Unable to read encrypted message file :",e)
		exit()

def read_pubkey_from_file(path_cert):
	try:
		file_cert = open(path_cert,'rb')
		return file_cert.read()
	except Exception as e:
		print("Unable to read public key file : ",e)
		exit()

# extended euclidian algorithm - iterative version adaptedfrom wikibooks
def egcd(a, b): 
	a,b = int(a),int(b)
	"""return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
	x0, x1, y0, y1 = 0, 1, 1, 0
	while a != 0:
		q, b, a = b // a, a, b % a
		y0, y1 = y1, y0 - q * y1
		x0, x1 = x1, x0 - q * x1
	return b,x0,y0

def coprimes(a,b):
	if(egcd(a,b)[0]==1):
		return True
	else:
		return False

def modinv(a, m):
	a,m = int(a),int(m)
	g, x, y = egcd(a, m)
	if g != 1:
		raise ValueError('Modular inverse of {} in base {} does not exist.'.format(a,m))
		exit()
	else:
		return x % m

# adapted from https://www.geeksforgeeks.org/find-number-co-prime-pairs-array/
# not optimized at all :)
def check_coprimes_all(arr, n) :
    for i in range(0, n-1) : 
        for j in range(i+1, n) : 
            if not(coprimes(arr[i], arr[j])): 
                return False
    return True 

def compute_Mis(glob_M,array_mod):
	array_Mis = []
	for n in array_mod:
		array_Mis.append(glob_M//int(n))
	return array_Mis

def compute_modular_inverses(array_Mis,array_mod):
	array_modinv = []
	for i,Mis in enumerate(array_Mis):
		array_modinv.append(modinv(Mis,array_mod[i]))
	return array_modinv

def compute_global_congruence(array_congr,array_Mis,array_modinv):
	K = 0
	for i,Mis in enumerate(array_Mis):
		K = K+(int(array_congr[i])*int(Mis)*int(array_modinv[i]))
	return K

def file_mode():
	array_mod = []
	array_exponent = []
	array_congr = []
	for i,n in enumerate(args.n):
		N,E = extract_pubkeyInfo(parse_der_pubkey(read_pubkey_from_file(n)))
		array_mod.append(N)
		array_congr.append(read_message_from_file(args.c[i]))
		array_exponent.append(E)
	if not array_exponent.count(array_exponent[0]) == len(array_exponent):
		print("All public exponents must be equals in order to decrypt the initial message")
		exit()
	return array_mod,array_congr,array_exponent[0]

	
def main():
	if not len(args.n) == len(args.c):
		print("Modulus or congruence relation missing")
		exit()

	if args.files:
		array_mod,array_congr,pubexp = file_mode()
	else:
		array_mod = args.n
		array_congr = args.c

	if not check_coprimes_all(array_mod,len(array_mod)):
		print("Modulus integer set must be pairwise coprime")
		exit()

	M = functools.reduce(lambda x,y : int(x)*int(y), array_mod)
	Mis = compute_Mis(M, array_mod)
	Yis = compute_modular_inverses(Mis,array_mod)

	K = compute_global_congruence(array_congr,Mis,Yis)%M

	print("\n x is congruent to {} \nmod {}".format(K,M))

	if args.files:
		K_great = gmpy.mpz(K)
		main_root = K_great.root(pubexp)
		if not main_root[1] == 1:
			print("\n {}th-root of m^e is not an integer. Check input message integrity.")
			exit()

		Solution = int(main_root[0])
		print("\n Decrypted m integer value : {}".format(Solution))
		print("\n Possible cleartext value : ")
		print(libnum.n2s(Solution))


if __name__ == '__main__':
	main()