from cryptBreak import cryptBreak
from BitVector import *

RandomInteger = 9999
bv = BitVector(intVal=RandomInteger, size=16)
decryptedMessage = cryptBreak("cipherText.txt", bv)
if 'Ferrari' in decryptedMessage:
    print(decryptedMessage)
    print("The key is: ", bv.get_bitvector_in_hex())
    print('Encryption broken!')
else:
    print('Encryption not broken!')