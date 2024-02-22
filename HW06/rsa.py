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
            print(self.p)


        # Read q from file
        with open(q_file, 'r') as file:
            self.q = int(file.read().strip())
            print(self.q)

        # Rest of the code...
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

    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        #hmmmmmmmmmmm
        
        return pow(plaintext, self.e, self.n)
    
if __name__ == "__main__":
    cipher = RSA(e=65537)
    if sys.argv[1] == "-g":
        cipher.key_generation(p_file=sys.argv[2], q_file=sys.argv[3])
        print("Keys generated")
    