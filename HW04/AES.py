import sys
from BitVector import *
import copy

AES_modulus = BitVector(bitstring='100011011')
def gee(keyword, round_constant, byte_sub_table):
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size=0)
    for i in range(4):
        newword += BitVector(intVal=byte_sub_table[rotated_word[i*8:i*8+8].intValue()], size=8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal=0x02), AES_modulus, 8)
    return newword, round_constant
def genTables(): # Generate the SBox and inverse SBox tables for AES byte substitution
        subBytesTable = []
        invSubBytesTable = []
        c = BitVector(bitstring='01100011')
        d = BitVector(bitstring='00000101')
        for i in range(0,256):
            a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            #for bit scrambling for SBox entries
            a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
            # For the decryption process
            b = BitVector(intVal=i, size=8)
            b1, b2, b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            invSubBytesTable.append(int(b))
        return subBytesTable, invSubBytesTable
class AES():
    def __init__(self, key_file:str) -> None:
        self.key = self.read_key(key_file)
        #print(self.key)
        self.encryption_sbox,self.decryption_sbox = genTables()
        self.key_schedule = self.gen_key_schedule_256(self.key)
    def gen_key_schedule_256(self, key_bv: BitVector) -> list:
        key_words = [None for i in range(60)]
        round_constant = BitVector(intVal=0x01, size=8)
        for i in range(8):
            key_words[i] = key_bv[i * 32: i * 32 + 32]
        for i in range(8, 60):
            if i % 8 == 0:
                #print(key_words)
                kw, round_constant = gee(key_words[i - 1], round_constant, self.encryption_sbox)
                key_words[i] = key_words[i - 8] ^ kw
            elif (i - (i // 8) * 8) < 4:
                key_words[i] = key_words[i - 8] ^ key_words[i - 1]
            elif (i - (i // 8) * 8) == 4:
                key_words[i] = BitVector(size=0)
                for j in range(4):
                    key_words[i] += BitVector(intVal=self.encryption_sbox[key_words[i - 1][j * 8:j * 8 + 8].intValue()], size=8)
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
    def to_state_array(self, bv: BitVector) -> list:
        return [[bv[j*32+i*8:j*32+i*8+8] for j in range(4)] for i in range(4)]
    def to_bit_vector(self, state_array: list) -> BitVector:
        bv = BitVector(size=0)
        for i in range(4):
            for j in range(4):
                bv += state_array[j][i]
        return bv
    def shift_rows(self, state_array: list) -> list:
        for i in range(1, 4):
            state_array[i] = state_array[i][i:] + state_array[i][:i]
        return state_array
    def one_round(self, bv: BitVector, round_key) -> BitVector:
        state_array = self.to_state_array(bv)
        for i in range(4):
            for j in range(4):
                state_array[i][j] = BitVector(intVal=self.encryption_sbox[state_array[i][j].intValue()], size=8)
        print("Step 3" , self.to_bit_vector(state_array).get_hex_string_from_bitvector())
        state_array = self.shift_rows(state_array)
        print("Step 4", self.to_bit_vector(state_array).get_hex_string_from_bitvector())
        state_array_copy = copy.deepcopy(state_array)
        constants = [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")]
        for i in range(4):
            for j in range(4):
                out = BitVector(size=8)
                for k in range(4):
                    out ^= state_array_copy[k][j].gf_multiply_modular(constants[k-i], AES_modulus, 8)
                state_array[i][j] = out
        output = self.to_bit_vector(state_array)
        print("Step 5", output.get_hex_string_from_bitvector())
        return output ^ round_key
    def encrypt(self, plaintext:str, ciphertext:str) -> None:
        #each round of AES involves the following 4 steps:
        #1. Single-byte Substitution

        #2. Row-wise permutation
        #3. Column-wise mixing
        #4. Key addition
        bv = BitVector(filename=plaintext)
        FILEOUT = open(ciphertext, 'w')
        #while bv.more_to_read:
        bitvec = bv.read_bits_from_file(128)
        print("Step 1", bitvec.get_hex_string_from_bitvector())
        if bitvec.length() > 0:
            if bitvec.length() < 128:
                bitvec.pad_from_right(128 - bitvec.length())
            key = self.key_schedule[0] + self.key_schedule[1] + self.key_schedule[2] + self.key_schedule[3]
            bitvec ^= key
            print("Step 2", bitvec.get_hex_string_from_bitvector())
            #for i in range(1, 14):
            i = 0
            key = self.key_schedule[(i+1)*4] + self.key_schedule[(i+1)*4+1] + self.key_schedule[(i+1)*4+2] + self.key_schedule[(i+1)*4+3]
            bitvec = self.one_round(bitvec, key)
            print("Step 6", bitvec.get_hex_string_from_bitvector())
            bitvec.write_to_file(FILEOUT)
        #return bv.write_to_file(FILEOUT)
        pass


if __name__ == "__main__":
    cipher = AES(key_file = sys.argv[3])

    if sys.argv[1] == "-e":
        cipher.encrypt(plaintext=sys.argv[2], ciphertext=sys.argv[4])
    else:
        sys.exit("Incorrect command syntax")