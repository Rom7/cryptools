#!/usr/bin/env python3

import ssl, socket
import argparse
import math
from factordb.factordb import FactorDB #pip install factordb-pycli
from oscrypto import keys, asymmetric, _openssl

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-hostname", help="Hostname serving target TLS certificate")
group.add_argument("-pubkey",help="Path to PEM/DER public key")
parser.add_argument("-p","--port",type=int, default=443)
parser.add_argument("-v","--verbose",action="store_true")
args = parser.parse_args()


def check_fdb(mod):
	f = FactorDB(mod)
	try:
		assert "200" in str(f.connect())
		stat = f.get_status()
		if(stat == "CF"):
			print("\nWarning : this modulus is not safe, factors are known")
		elif stat == "FF":
			factors = f.get_factor_list()
			print("\n Warning : this modulus has been fully factorised, factors known : \n")
			print(factors)
		else:
			print("\nNo factors known")
	except AssertionError:
		print("Unable to connect to FactorDB")

def read_pubkey_from_file(path_cert):
	try:
		file_cert = open(path_cert,'rb')
		return file_cert.read()
	except Exception as e:
		print("Unable to read public key file : ",e)
		exit()

def retrieve_cert(hostname,port):
	ctx = ssl.create_default_context()
	s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
	s.connect((hostname, port))
	der = s.getpeercert(binary_form=True)
	return der

def parse_der_cert(der_cert):
	cert = asymmetric.load_certificate(keys.parse_certificate(der_cert))
	return cert

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

def main():
	if args.hostname:
		N,E = extract_pubkeyInfo(parse_der_cert(retrieve_cert(args.hostname,args.port)))
	elif args.pubkey:
		N,E = extract_pubkeyInfo(parse_der_pubkey(read_pubkey_from_file(args.pubkey)))
	if (args.verbose):
		N_length = round(math.log(N,2))
		print("Decimal value of modulus ({} bits length) :\n{}".format(N_length,N))
		print("Public exponent : {}".format(E))
	check_fdb(N)

if __name__ == '__main__':
	main()