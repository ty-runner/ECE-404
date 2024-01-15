from cryptBreak import cryptBreak
from BitVector import *

for i in range(0, 2**16):
    bv = BitVector(intVal=i, size=16)
    bv_str = bv.get_bitvector_in_hex()
    print("The random number in bits is: ", bv_str)
    decryptedMessage = cryptBreak("cipherText.txt", bv_str)
    if 'Ferrari' in decryptedMessage:
        print(decryptedMessage)
        print("The key is: ", bv.get_bitvector_in_hex())
        print('Encryption broken!')
        break
    else:
        print('Encryption not broken!')