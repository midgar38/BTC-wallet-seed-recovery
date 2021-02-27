#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.encoding import to_hexstring
import hmac, hashlib
import ecdsa
from ecdsa import SigningKey, NIST384p
from ecdsa.curves import SECP256k1
import binascii
import pycoin

from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey
from ecdsa import VerifyingKey, NIST256p

import base58

import itertools as it
import random

f = open('english.txt', 'r+')
#rajout de .strip() pour enlever le /n à la fin de chaque mot
lines = [line.strip() for line in f.readlines()]
f.close()
# print(lines)
# print(lines[0])

# print("mot chance est", random.choice(lines))

count=0
while True:
    #Generation of the passphrases
    my_dict={'A':['army'],'B':['excuse'],'C':['hero'], 
             'D':['wolf'], 'E':['disease'],
             'F':['liberty'], 'G':['moral'], 'H': ['diagram'], 'I': [random.choice(lines)], 'J': [random.choice(lines)],
             'K': [random.choice(lines)], 'L': [random.choice(lines)]}
    allNames = sorted(my_dict)
    combinations = it.product(*(my_dict[Name] for Name in allNames))
    # print(list(combinations))
    
    # words1 = Mnemonic().generate()
    # print("words1 is", words1)
    # print(to_hexstring(Mnemonic().to_seed(words1)))
    
    test_list=[list(i) for i in list(combinations)] # list of lists
    words=[]   
    for i in range(0,len(test_list)):
        words.append(' '.join(test_list[i]))
        #words=' '.join(test_list[i])
        # m=to_hexstring(Mnemonic().to_seed(words))

    # print(words)
    # print(words[1]) 
    
    #test
    # my_str = "hello world"
    # my_str_as_bytes = str.encode(my_str)
    # print("my string is", my_str_as_bytes)
    #convert list words into list of bytes
    words_bytes=[]
    words_bytes=[str.encode(word) for word in words]
    
    # print(words_bytes)
    
    root_seed=[]
    for i in range(0,len(words)):
        root_seed.append(hashlib.pbkdf2_hmac('sha512', words_bytes[i], b'mnemonic', 2048).hex())
       
    # print(root_seed)
    
    root_seed_bytes=[str.encode(seed) for seed in root_seed]
    
    root_private_key=[]
    for i in range(0,len(words)):
        root_private_key.append(hmac.new(root_seed_bytes[i], msg=None, digestmod=hashlib.sha512).hexdigest())
    
    # print(root_private_key)
    
    master_private_key=[] #first half of rot private key
    master_private_key2=[]
    for i in range(0,len(words)):
        master_private_key.append(root_private_key[i][0:len(root_private_key[i])//2])
        
    # print(master_private_key)
    
    public_key=[]
    for i in range(0,len(words)):
        public_key.append(ecdsa.SigningKey.from_string(bytes.fromhex(master_private_key[i]), curve=ecdsa.SECP256k1).verifying_key)
    
    # print(public_key)
    
    #conversion public key en string in hex
    public_key_string=[]
    public_key_string=[word.to_string().hex() for word in public_key]
    # print(public_key_string)
    
    #Now you have to add "04", p 72, this is an uncompressed public key
    # uncompressed_pk = '04' + test_string.hex()
    uncompressed_pk=[]
    for i in range(0,len(words)):
        uncompressed_pk=['04' + word for word in public_key_string]
    
    # print(uncompressed_pk)
    
    #compressed_pk
    compressed_pk=[] 
    for i in range(0,len(words)):
        compressed_pk.append(VerifyingKey.from_string(bytearray.fromhex(uncompressed_pk[i]), curve=ecdsa.SECP256k1).to_string("compressed").hex())
    # print(compressed_pk)  #OK
    
    
    compressed_pk_bytes=[str.encode(pk) for pk in compressed_pk]
    # print(compressed_pk_bytes)  #OK
    
    
    compressed_pk_sha256=[]
    for i in range(0,len(words)):
    #     compressed_pk_sha256=[hashlib.sha256(compressed_pk_bytes[i]).hexdigest()]
    # print(compressed_pk_sha256)  #problem
        compressed_pk_sha256.append(hashlib.sha256(compressed_pk_bytes[i]).hexdigest())
    # print(compressed_pk_sha256)
    
    compressed_pk_sha256_bytes=[]
    compressed_pk_sha256_bytes=[str.encode(pk) for pk in compressed_pk_sha256]
    # print(compressed_pk_sha256_bytes)
    
    
    BTC_address_hex=[]
    for i in range(0,len(words)):
        BTC_address_hex.append(hashlib.new('ripemd160', compressed_pk_sha256_bytes[i]).hexdigest())
    # print(BTC_address_hex)
    
    prepend=[]
    for i in range(0,len(words)):
        prepend=['05' + word for word in BTC_address_hex]
    # print(prepend)
    
    prepend_bytes=[]
    prepend_bytes=[str.encode(pk) for pk in prepend]
    # print(prepend_bytes)
    
    #double sha256
    double_sha256_1=[]
    for i in range(0,len(words)):
        double_sha256_1.append(hashlib.sha256(prepend_bytes[i]).hexdigest())
        # double_sha256_1=[hashlib.sha256(word).hexdigest() for word in prepend_bytes]
        
    # print(double_sha256_1)
    
    double_sha256_1_bytes=[]
    double_sha256_1_bytes=[str.encode(pk) for pk in double_sha256_1]
    
    
    double_sha256_2=[]
    for i in range(0,len(words)):
        double_sha256_2.append(hashlib.sha256(double_sha256_1_bytes[i]).hexdigest())
    # print(double_sha256_2)
    
    #checksum calculations
    checksum=[]
    for i in range(0,len(words)):
        checksum.append(double_sha256_2[i][:8])
    # print(checksum)
    
    appendchecksum=[]
    for i in range(0,len(words)):
        appendchecksum.append(prepend[i]+checksum[i])
    
    # print(appendchecksum)
    
    #Final BTC address in base58:
    bitcoinAddress=[]
    for i in range(0,len(words)):
        bitcoinAddress.append(base58.b58encode(binascii.unhexlify(appendchecksum[i])))
    # print("Les adresses BTC sont", bitcoinAddress)
    
    #Pour passer de bytes à string
    bitcoinAddress_decode=[]
    bitcoinAddress_decode=[btc.decode("utf-8") for btc in bitcoinAddress]
    print("Les adresses BTC sont", bitcoinAddress_decode)


#Compare the list to Alistair's address: 3HX5tttedDehKWTTGpxaPAbo157fnjn89s
    for address in bitcoinAddress_decode:
        if '3HX5tttedDehKWTTGpxaPAbo157fnjn89s' == address:
            print(bitcoinAddress_decode.index("3HX5tttedDehKWTTGpxaPAbo157fnjn89s"))
            print("C'est gagné")
            break
        
    count=count+1
    print("The count is ", count)
        
    # else:
    #     print("C'est perdu")


#while loop implementation, example

# while True:
#     n = raw_input("Please enter 'hello':")
#     if n.strip() == 'hello':
#         break




############################

