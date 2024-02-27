from BitVector import *
import sys
import random
import binascii
from PrimeGenerator import *
from solve_pRoot import *
#1. generate 3 sets of public and private keys with e = 3
#2. encrypts the given plaintext with each of the 3 public keys. (3 ciphertexts after this step)
#3. Take the three ciphertexts generated in step 2 and use the CRT to recover the original plaintext.
class RSA():
    def __init__(self, e) -> None:
        self.e = e
        self.n1 = None
        self.n2 = None
        self.n3 = None

        self.d1 = None
        self.d2 = None
        self.d3 = None

        self.p1 = None
        self.p2 = None
        self.p3 = None

        self.q1 = None
        self.q2 = None
        self.q3 = None

        self.phi1 = None
        self.phi2 = None
        self.phi3 = None

        self.public_key1 = None
        self.public_key2 = None
        self.public_key3 = None

        self.private_key1 = None
        self.private_key2 = None
        self.private_key3 = None
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
    def key_generation(self) -> None:
        # Generate 3 different p's
        prime_generator = PrimeGenerator(bits=128)
        self.p1 = prime_generator.findPrime()
        self.p2 = prime_generator.findPrime()
        self.p3 = prime_generator.findPrime()
        
        # Generate 3 different q's
        self.q1 = prime_generator.findPrime()
        self.q2 = prime_generator.findPrime()
        self.q3 = prime_generator.findPrime()

        # Calculate n1-3 = p * q
        self.n1 = self.p1 * self.q1
        self.n2 = self.p2 * self.q2
        self.n3 = self.p3 * self.q3

        # Calculate phi(n) = (p-1)(q-1)
        self.phi1 = (self.p1 - 1) * (self.q1 - 1)
        self.phi2 = (self.p2 - 1) * (self.q2 - 1)
        self.phi3 = (self.p3 - 1) * (self.q3 - 1)
        # Ensure gcd(phi, e) = 1
        while self.gcd(self.phi1, self.e) != 1 or self.phi1 % 3 == 0:
            self.p1 = prime_generator.findPrime()
            self.q1 = prime_generator.findPrime()
            self.n1 = self.p1 * self.q1
            self.phi1 = (self.p1 - 1) * (self.q1 - 1)

        while self.gcd(self.phi2, self.e) != 1 or self.phi2 % 3 == 0:
            self.p2 = prime_generator.findPrime()
            self.q2 = prime_generator.findPrime()
            self.n2 = self.p2 * self.q2
            self.phi2 = (self.p2 - 1) * (self.q2 - 1)

        while self.gcd(self.phi3, self.e) != 1 or self.phi3 % 3 == 0:
            self.p3 = prime_generator.findPrime()
            self.q3 = prime_generator.findPrime()
            self.n3 = self.p3 * self.q3
            self.phi3 = (self.p3 - 1) * (self.q3 - 1)

        # Calculate for the private exponent a value d such that d = e^-1 mod phi(n)
        self.d1 = self.mod_inverse(self.e, self.phi1)
        self.d2 = self.mod_inverse(self.e, self.phi2)
        self.d3 = self.mod_inverse(self.e, self.phi3)
        # Public key = [e,n]
        self.public_key1 = (self.e, self.n1)
        self.public_key2 = (self.e, self.n2)
        self.public_key3 = (self.e, self.n3)

        # Private key = [d,n]
        self.private_key1 = (self.d1, self.n1)
        self.private_key2 = (self.d2, self.n2)
        self.private_key3 = (self.d3, self.n3)

    def encrypt(self, plaintext:str, enc1:str, enc2:str, enc3:str, mods_used:str) -> None:
        # Read plaintext from file
        plaintext_bv = BitVector(filename=plaintext)
        self.key_generation()
        print(self.public_key1, self.public_key2, self.public_key3)
        with open(enc1, 'w') as file:
            while plaintext_bv.more_to_read:
                bitvec = plaintext_bv.read_bits_from_file(128)
                if bitvec.length() < 128:
                    bitvec.pad_from_right(128 - bitvec.length())
                bitvec.pad_from_left(128)
                plain_num = int(bitvec)
                ciphertext = pow(plain_num, self.e, self.n1)
                output = BitVector(intVal=ciphertext, size=256)
                file.write(output.get_bitvector_in_hex())
        plaintext_bv = BitVector(filename=plaintext)
        with open(enc2, 'w') as file:
            while plaintext_bv.more_to_read:
                bitvec = plaintext_bv.read_bits_from_file(128)
                if bitvec.length() < 128:
                    bitvec.pad_from_right(128 - bitvec.length())
                bitvec.pad_from_left(128)
                plain_num = int(bitvec)
                ciphertext = pow(plain_num, self.e, self.n2)
                output = BitVector(intVal=ciphertext, size=256)
                file.write(output.get_bitvector_in_hex())
        plaintext_bv = BitVector(filename=plaintext)
        with open(enc3, 'w') as file:
            while plaintext_bv.more_to_read:
                bitvec = plaintext_bv.read_bits_from_file(128)
                if bitvec.length() < 128:
                    bitvec.pad_from_right(128 - bitvec.length())
                bitvec.pad_from_left(128)
                plain_num = int(bitvec)
                ciphertext = pow(plain_num, self.e, self.n3)
                output = BitVector(intVal=ciphertext, size=256)
                file.write(output.get_bitvector_in_hex())
        with open(mods_used, 'w') as file:
            file.write(str(self.n1) + '\n' + str(self.n2) + '\n' + str(self.n3))

    def crack(self, enc1:str, enc2:str, enc3:str, mods_used:str, output_file:str) -> None:
        # Read ciphertext from file
        with open(enc1, 'r') as file:
            ciphertext_bv1 = BitVector(hexstring=file.read())
        with open(enc2, 'r') as file:
            ciphertext_bv2 = BitVector(hexstring=file.read())
        with open(enc3, 'r') as file:
            ciphertext_bv3 = BitVector(hexstring=file.read())
        with open(mods_used, 'r') as file:
            self.n1 = int(file.readline())
            self.n2 = int(file.readline())
            self.n3 = int(file.readline())
        M = self.n1 * self.n2 * self.n3
        reduced_n1 = int(M / self.n1)
        reduced_n2 = int(M / self.n2)
        reduced_n3 = int(M / self.n3)
        n1_bv = BitVector(intVal=reduced_n1)
        n2_bv = BitVector(intVal=reduced_n2)
        n3_bv = BitVector(intVal=reduced_n3)
        self.d1 = int(n1_bv.multiplicative_inverse(BitVector(intVal=self.n1)))
        self.d2 = int(n2_bv.multiplicative_inverse(BitVector(intVal=self.n2)))
        self.d3 = int(n3_bv.multiplicative_inverse(BitVector(intVal=self.n3)))

        # Perform CRT to recover the original plaintext
        with open(output_file, 'wb') as file:
            while ciphertext_bv1.length() > 0 and ciphertext_bv2.length() > 0 and ciphertext_bv3.length() > 0:
                bitvec1 = ciphertext_bv1[:256]
                bitvec2 = ciphertext_bv2[:256]
                bitvec3 = ciphertext_bv3[:256]
                ciphertext_bv1 = ciphertext_bv1[256:]
                ciphertext_bv2 = ciphertext_bv2[256:]
                ciphertext_bv3 = ciphertext_bv3[256:]
                if bitvec1.length() < 256:
                    bitvec1.pad_from_right(256 - bitvec1.length())
                if bitvec2.length() < 256:
                    bitvec2.pad_from_right(256 - bitvec2.length())
                if bitvec3.length() < 256:
                    bitvec3.pad_from_right(256 - bitvec3.length())
                cipher_num1 = int(bitvec1)
                cipher_num2 = int(bitvec2)
                cipher_num3 = int(bitvec3)
                result = (cipher_num1 * reduced_n1 * self.d1 + cipher_num2 * reduced_n2 * self.d2 + cipher_num3 * reduced_n3 * self.d3)
                plaintext_num = solve_pRoot(3, result)
                print(plaintext_num)
                plaintext_bv = BitVector(intVal=plaintext_num, size=256)
                plaintext_bv = plaintext_bv[128:256]
                plaintext_bv.write_to_file(file)

if __name__ == "__main__":
    cipher = RSA(e=3)
    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], enc1=sys.argv[3], enc2=sys.argv[4], enc3=sys.argv[5], mods_used=sys.argv[6])
    if sys.argv[1] == "-c":
        cipher.crack(enc1=sys.argv[2], enc2=sys.argv[3], enc3=sys.argv[4], mods_used=sys.argv[5], output_file=sys.argv[6])

# py breakRSA.py -c enc1.txt enc2.txt enc3.txt n_1_2_3.txt cracked.txt
# py breakRSA.py -e message.txt enc1.txt enc2.txt enc3.txt n_1_2_3.txt
    