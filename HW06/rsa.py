from BitVector import *
import sys
import random
import binascii

class RSA():
    def __init__(self, e) -> None:
        self.e = e
        self.n = None
        self.d = None
        self.p = None
        self.q = None
        self.phi = None
        self.public_key = None
        self.private_key = None
    def gcd(self, a:int, b:int) -> int:
        while b != 0:
            a, b = b, a % b
        return a
    def mod_inverse(self, a, m):
        m0, x0, x1 = m, 0, 1
        while a > 1:
            q = a // m
            m, a = a % m, m
            x0, x1 = x1 - q * x0, x0
        return x1 + m0 if x1 < 0 else x1
    def key_generation(self, p_file:str, q_file:str) -> None:
        # Read p from file
        with open(p_file, 'r') as file:
            self.p = int(file.read().strip())

        # Read q from file
        with open(q_file, 'r') as file:
            self.q = int(file.read().strip())
        # Calc mod n = p * q
        self.n = self.p * self.q
        # Calc phi(n) = (p-1)(q-1)
        self.phi = (self.p-1)*(self.q-1)
        # calculate for the private exponent a value d such that d = e^-1 mod phi(n)
        self.d = self.mod_inverse(self.e, self.phi)
        # Public key = [e,n]
        self.public_key = (self.e, self.n)
        # Private key = [d,n]
        self.private_key = (self.d, self.n)

    def encrypt(self, plaintext:str, ciphertext_file:str) -> None:
        # Read plaintext from file
        plaintext_bv = BitVector.BitVector(filename=plaintext)
        self.key_generation(sys.argv[3], sys.argv[4])
        self.e, self.n = self.public_key
        with open(ciphertext_file, 'w') as file:
            while plaintext_bv.more_to_read:
                bitvec = plaintext_bv.read_bits_from_file(128)
                if bitvec.length() < 128:
                    bitvec.pad_from_right(128 - bitvec.length())
                bitvec.pad_from_left(128)
                plain_num = int(bitvec)
                ciphertext = pow(plain_num, self.e, self.n)
                output = BitVector.BitVector(intVal=ciphertext, size=256)
                file.write(output.get_bitvector_in_hex())
        print("Encryption done")   
    def decrypt(self, ciphertext:str, recovered_plaintext:str) -> None:
        # Read ciphertext from file
        with open(ciphertext, 'r') as file:
            ciphertext_bv = BitVector(hexstring=file.read())
        self.key_generation(sys.argv[3], sys.argv[4])
        self.d, self.n = self.private_key
        with open(recovered_plaintext, 'wb') as file:
            while ciphertext_bv.length() > 0:
                bitvec = ciphertext_bv[:256]
                ciphertext_bv = ciphertext_bv[256:]
                if bitvec.length() < 256:
                    bitvec.pad_from_right(256 - bitvec.length())
                cipher_num = int(bitvec)
                plaintext = pow(cipher_num, self.d, self.n)
                output = BitVector(intVal=plaintext, size=256)
                output = output[-128:]
                output.write_to_file(file)
        print("Decryption done")
if __name__ == "__main__":
    cipher = RSA(e=65537)
    if sys.argv[1] == "-g":
        cipher.key_generation(p_file=sys.argv[2], q_file=sys.argv[3])
        print("Keys generated")
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext_file=sys.argv[5])
    if sys.argv[1] == "-d":
        cipher.decrypt(ciphertext=sys.argv[2], recovered_plaintext=sys.argv[5])
    