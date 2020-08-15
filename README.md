# cryptools
Some crypto-related scripts  
Useful to solve some challenges or quick tests  


## HIBF.py
This script check if a given RSA modulus has been factorised, using factordb.com (thanks to https://github.com/ryosan-470/factordb-pycli )  
Handle PEM or DER encoded RSA public keys (-pubkey)  
Can retrieve a TLS certificate and check the modulus if it uses RSA (-hostname ; it performs a certificate validation first)  
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


## copper_stereo.sage
An application of Coppersmith's attack for stereotyped messages using SageMath (v9).  
This theroem is based on LLL basis reduction algorithm and can be used when stereotyped messages (e.g. : logs) are encrypted using raw-RSA encryption scheme (e.g. without any padding system)  

Like most of attacks deriving from Coppersmith's theorem, a low public exponent E is very helpful (since LLL algorithm tries to find roots of a polynomial of degree E at most)  
Further conditions are also mandatory : size of the unknown part of the message must be smaller than N^(1/e)  
If you are not sure about how long your unknown part is, you can easily twaek this script to test various size (i.e. adding some "\*")  

ex : sage copper_stereo.sage -n 120279682020498722984378664929957269995938437640582887988946285242233892284417856793385609226397118311238116720585802476226490347446060038688325286339720009935596353781452405089788532241908988880482772050730726814381672275409427764206380766693159708551111271803383167352452802991608314812878134420560882676109 -e 3 -c 38136682505766039559183446229674917251753001810843406283848627410563692534650927547349056899583207362946357233967856736264217071042350719553284683863158441231442974425888716015558761605868349441999675449974223613135532782350921534207873944341657719329194849592044365732569768296828022226690098363220197110347 -m "Your password is ******** and you should change it"