import sys
from BitVector import *

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []
invSubBytesTable = []
def gee(keyword, round_constant, byte_sub_table):
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size=0)
    for i in range(4):
        newword += BitVector(intVal=byte_sub_table[rotated_word[i*8:i*8+8].intValue()], size=8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal=0x02), AES_modulus, 8)
    return newword, round_constant
class AES():
    def __init__(self, key_file:str) -> None:
        self.key = self.read_key(key_file)
        self.key_schedule = self.gen_key_schedule_256(self.key)
        self.genTables()
        self.encryption_sbox = subBytesTable
        self.decryption_sbox = invSubBytesTable
    def genTables(): # Generate the SBox and inverse SBox tables for AES byte substitution
        for i in range(256):
            a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            #for bit scrambling for SBox entries
            a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ BitVector(intVal=0x63)
            subBytesTable.append(int(a))
            # For the decryption process
            b = BitVector(intVal=i, size=8)
            b1, b2, b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ BitVector(intVal=0x05)
            check = b.gf_MI(AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            invSubBytesTable.append(int(b))
    def gen_key_schedule_256(self, key_bv: BitVector) -> list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal=0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i * 32: i * 32 + 32]
        for i in range(8, 60):
            if i % 8 == 0:
                print(key_words)
                kw, round_constant = gee(key_words[i - 1], round_constant, subBytesTable)
                key_words[i] = key_words[i - 8] ^ kw
            elif (i - (i // 8) * 8) < 4:
                key_words[i] = key_words[i - 8] ^ key_words[i - 1]
            elif (i - (i // 8) * 8) == 4:
                key_words[i] = BitVector(size=0)
                for j in range(4):
                    key_words[i] += BitVector(intVal=subBytesTable[key_words[i - 1][j * 8:j * 8 + 8].intValue()], size=8)
                key_words[i] ^= key_words[i - 8]
            elif ((i - (i // 8) * 8) > 4) and ((i - (i // 8) * 8) < 8):
                key_words[i] = key_words[i - 8] ^ key_words[i - 1]
            else:
                sys.exit("error in key scheduling algo for i = %d" % i)
        return key_words
    def read_key(self, key_file:str) -> BitVector:
        with open(key_file) as file:
            key = file.read()
        return BitVector(textstring=key)
    
    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        #each round of AES involves the following 4 steps:
        #1. Single-byte Substitution
        print(subBytesTable)

        #2. Row-wise permutation
        #3. Column-wise mixing
        #4. Key addition
        bv = BitVector(filename=plaintext)
        FILEOUT = open(ciphertext, 'wb')
        #return bv.write_to_file(FILEOUT)
        pass


if __name__ == "__main__":
    cipher = AES(key_file = sys.argv[3])

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    else:
        sys.exit("Incorrect command syntax")