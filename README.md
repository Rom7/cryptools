# cryptools
Some crypto-related scripts  
Useful to solve some challenges or quick tests  


## HIBF.py
This script check if a given RSA modulus has been factorised, using factordb.com (thanks to https://github.com/ryosan-470/factordb-pycli )  
Handle PEM or DER encoded RSA public keys (-pubkey)  
Can retrieve a TLS certificate and check de modulus if it uses RSA (-hostname ; it performs a certificate validation first)  
ex : ./hibf.py -v -hostname github.com ; ./hibf.py -v -pubkey mypubkey.pem 


## FCWL.py
This is an application of the chinese remainder theorem. Works directly with integers (--integers) or with RSA (--files)
input modulos as an array of integers or pubkey files (-n)  
input congurences as an array of integers or base64 encoded data (-c)  
As you know, this theorem can help you to recover a plaintext encrypted with RSA (under certain conditions, such as : e is small, all modulos must be pairwise coprimes, messages were encrypted with the same public exponent...)  

ex : ./fcwl.py --integers -c 3 4 5 -n 17 11 6 ; this solves the following system :  
x ≅ 3[7] ; x ≅ 4[11] ; x ≅ 5[6] 
Solution will be of the form : x ≅ K\[17\*11\*6] 

ex with RSA : ./fcwl.py --files -c enc_message1.txt enc_message2.txt encmessage3.txt -n pubkey1.pem pubkey2.pem pubkey3.pem  
Assuming enc_messagei.txt was encrypted with pubkeyi.pem (so order matters). This will work if e << ∏(modulus) and try to print out the original message in plaintext
