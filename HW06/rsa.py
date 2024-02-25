import BitVector
import sys
import random

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
        with open(plaintext, 'r') as file:
            plaintext = file.read()
        self.key_generation(sys.argv[3], sys.argv[4])
        self.e, self.n = self.public_key
        ciphertext = [pow(ord(char), self.e, self.n) for char in plaintext]
        ciphertext = ''.join([str(char) for char in ciphertext])
        with open(ciphertext_file, 'w') as file:
            file.write(str(ciphertext))     
        print("Encryption done")   
    def decrypt(self, ciphertext:str, recovered_plaintext:str) -> None:
        # Read ciphertext from file
        with open(ciphertext, 'r') as file:
            ciphertext = file.read()
        self.key_generation(sys.argv[3], sys.argv[4])
        self.d, self.n = self.private_key
        plaintext = ''.join([chr(pow(int(char), self.d, self.n)) for char in ciphertext])
        with open(recovered_plaintext, 'w') as file:
            file.write(plaintext)
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
    