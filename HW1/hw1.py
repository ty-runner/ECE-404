from cryptBreak import cryptBreak
from BitVector import *

for i in range(0, 2**16):
    bv = BitVector(intVal=i, size=16)
    decryptedMessage = cryptBreak("cipherText.txt", bv)
    if 'Ferrari' in decryptedMessage:
        print(decryptedMessage)
        print('Encryption broken!')
        print("The key in ASCII is: ", bv.get_bitvector_in_ascii())
        print("The key in hex is: ", bv.get_bitvector_in_hex())
        print("The key is: ", bv)
        break
    else:
        print('Encryption not broken!')