import sys
from BitVector import *

class AES():
    def __init__(self, key_file:str) -> None:
        

    
    def encrypt(self, plaintext:str, ciphertext:str()) -> None:
        pass


if __name__ == "__main__":
    cipher = AES(keyfile = sys.argv[3])

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    else:
        sys.exit("Incorrect command syntax")