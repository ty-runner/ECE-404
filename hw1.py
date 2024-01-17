from cryptBreak import cryptBreak
from BitVector import *

for i in range(0, 2**16):
    bv = BitVector(intVal=i, size=16)
    bv_str = bv.get_bitvector_in_hex()
    decryptedMessage = cryptBreak("cipherText.txt", bv_str)
    if 'Ferrari' in decryptedMessage:
        print(decryptedMessage)
        print('Encryption broken!')
        print("The key in ASCII is: ", bv.get_bitvector_in_ascii())
        print("The key in hex is: ", bv.get_bitvector_in_hex())
        print("The key in binary is: ", bv)
        break
    else:
        print('Encryption not broken!')