#!/usr/bin/env sage
# Coppersmith's theorem application for stereotyped raw-RSA message decryption 
# Crypto.Util is provided by pycryptodome


import argparse
import math
from Crypto.Util.number import long_to_bytes as l2b
from Crypto.Util.number import bytes_to_long as b2l

parser = argparse.ArgumentParser()
parser.add_argument("-n",help="Modulus value of public key",required=True,type=int)
parser.add_argument("-c",help="Value of raw-encrypted message, using associated e and n",required=True,type=int)
parser.add_argument("-e",help="Public exponent value of public key",required=True,type=int)
parser.add_argument("-m",help="Cleartext stereotyped message, using '*' for unknown characters",required=True)
args = parser.parse_args()

message = args.m
N = args.n
N_size = math.log2(N)
prefix = message.split("*")[0]
suffix = message.split("*")[-1]
unknown_len = message.count("*")
message = message.encode("utf-8")
message = message.replace(b'*',b'\x00',unknown_len)
X_size = ((256**unknown_len)**args.e) 
X_apex_size = math.log2(X_size) #Approx unknown size

#First and main condition is : x must be smaller than N^(1/e) <--> x^e < N
if X_apex_size >= N_size: 
	print("Unknown too large / public exponent too large / modulus too small : Coppersmith's theorem can't be used \n")
	exit()

def solver(eps_num):
	m_bin = b2l(message)
	P.<x> = PolynomialRing(Zmod(N), implementation='NTL')
	pol = ((m_bin + (256**len(suffix))*x)^args.e) - args.c
	pol=pol.monic() 
	roots = pol.small_roots(epsilon=1/20) # This will compute the roots of a smaller but "equivalent" polynomial
	if len(roots) == 0:
		return False
	else:
		print("Potential solution(s) found :")
		for root in roots:
			print(root, l2b(root))
			print(prefix,l2b(root),suffix)
		return True

def main():
	for eps in [10,15,20,30,40]:
		if not solver(eps):
			print("No solution found, tweaking espilon value...")
		else:
			exit()
	print("No solution found, solution is unlikely to exist")
	exit()

if __name__ == '__main__':
	main()