# Write an Object Oriented Python [1] program that implements the full DES
# algorithm. Refer to Lecture 3 as it outlines the key steps to implementing
# DES. Given an encryption key and some plaintext, your program must produce the correct encryption and decryption results.

# An explanation of the command-line syntax is as follows:
# • Encryption (indicated with the -e argument in line 1)
# – perform DES encryption on the plaintext in message.txt using the key in key.txt, and write the ciphertext to a file called
# encrypted.txt
# – You can assume that message.txt and key.txt contain text
# strings (i.e. ASCII characters)
# – However, the final ciphertext should be saved as a single-line hex
# string

# • Decryption (indicated with the -d argument in line 2)
# – perform DES decryption on the ciphertext in encrypted.txt
# using the key in key.txt, and write the recovered plaintext to
# decrypted.txt

from BitVector import *
import sys

class DES():
    #class constructor - when creating a DES object,
    #the class's constructor is called and the instance variables are initialized

    #note that the constructor specifies each instance of DEs
    #be created with a key file (str)
    def __init__(self,key):
        #within the constructor, initialize the instance variables

        #these could be the s-boxes, permutation boxes, etc.
        self.expansion_permutation =  [31, 0, 1, 2, 3, 4,
                                        3, 4, 5, 6, 7, 8,
                                        7, 8, 9, 10, 11, 12,
                                        11, 12, 13, 14, 15, 16,
                                        15, 16, 17, 18, 19, 20,
                                        19, 20, 21, 22, 23, 24,
                                        23, 24, 25, 26, 27, 28,
                                        27, 28, 29, 30, 31, 0]
        self.s_boxes = {i: None for i in range(8)}
        self.s_boxes[0] = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
                            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
                            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
                            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]
        self.s_boxes[1] = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
                            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
                            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
                            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]
        self.s_boxes[2] = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
                            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
                            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
                            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]
        self.s_boxes[3] = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
                            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
                            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
                            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]
        self.s_boxes[4] = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
                            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
                            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
                            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]
        self.s_boxes[5] = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
                            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
                            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
                            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]
        self.s_boxes[6] = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
                            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
                            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
                            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]
        self.s_boxes[7] = [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
                            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 10, 14, 9, 2],
                            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
                            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
        self.p_box = [15, 6, 19, 20, 28, 11,
                        27, 16, 0, 14, 22, 25,
                        4, 17, 30, 9, 1, 7,
                        23, 13, 31, 26, 2, 8,
                        18, 12, 29, 5, 21, 10,
                        3, 24]
        self.key_permutation_1 = [56, 48, 40, 32, 24, 16, 8,
                                    0, 57, 49, 41, 33, 25, 17,
                                    9, 1, 58, 50, 42, 34, 26,
                                    18, 10, 2, 59, 51, 43, 35,
                                    62, 54, 46, 38, 30, 22, 14,
                                    6, 61, 53, 45, 37, 29, 21,
                                    13, 5, 60, 52, 44, 36, 28,
                                    20, 12, 4, 27, 19, 11, 3]
        self.key_permutation_2 = [13, 16, 10, 23, 0, 4,
                                    2, 27, 14, 5, 20, 9,
                                    22, 18, 11, 3, 25, 7,
                                    15, 6, 26, 19, 12, 1,
                                    40, 51, 30, 36, 46, 54,
                                    29, 39, 50, 44, 32, 47,
                                    43, 48, 38, 55, 33, 52,
                                    45, 41, 49, 35, 28, 31]
        self.shifts_for_round_key_gen = [1, 1, 2, 2,
                                            2, 2, 2, 2,
                                            1, 2, 2, 2,
                                            2, 2, 2, 1]
        self.key = self.read_key(key)
    def read_key(self, key_file):
        with open(key_file, 'r') as key:
            key = key.read()
        print(key)
        key = BitVector(textstring=key)
        return key
    def generate_round_keys(self, encryption_key):
        round_keys = []
        key = encryption_key.deep_copy()
        for round_num in range(16):
            [LKey, RKey] = key.divide_into_two()
            #perform the left circular shift on the two halves
            shift = self.shifts_for_round_key_gen[round_num]
            LKey << shift
            RKey << shift
            #perform the permutation on the two halves
            key = LKey + RKey
            round_key = key.permute(self.key_permutation_2)
            round_keys.append(round_key)
        return round_keys
    #subsitution needed for the right half of the input in each round
    #this does not include XORing with the round key, that must be carried out on the expanded right-half block
    #before it is subject to the S-box based substitution step here
    def substitute(self, expanded_half_block):
        #substitutes each byte in the expanded half block using the s-boxes
        #returns the substituted half block
        output = BitVector(size=32)
        segments = [expanded_half_block[i*6:i*6+6] for i in range(8)]
        for s_index in range(len(segments)):
            row = 2*segments[s_index][0] + segments[s_index][-1]
            column = int(segments[s_index][1:-1])
            output[s_index*4:s_index*4+4] = BitVector(intVal=self.s_boxes[s_index][row][column], size=4)
        return output
    
    def encrypt(self, message_file, outfile):
        #encrypts the contents of the message file and writes the ciphertext to the outfile
        #read the message file
        message = BitVector(filename=message_file)
        outfile = open(outfile, 'w')
        #get the key
        key = self.key
        #perform the initial permutation on the key
        key = key.permute(self.key_permutation_1)
        #generate the round keys
        round_keys = self.generate_round_keys(key)
        #split the message into two halves
        while message.more_to_read:
            bv = message.read_bits_from_file(64)
            if len(bv) < 64:
                bv.pad_from_right(64-len(bv))
            [L, R] = bv.divide_into_two()
            print("First block as a bit vector:", L.get_hex_string_from_bitvector(), ",", R.get_hex_string_from_bitvector())
            #16 rounds of DES
            for round_num in range(1):
                #perform the expansion permutation on the right half
                expanded_R = R.permute(self.expansion_permutation)
                print("Expanded Right Block:", expanded_R.get_hex_string_from_bitvector())
                #XOR the expanded half with the round key
                expanded_R ^= round_keys[round_num]
                print("XOR Expanded Right Block:", expanded_R.get_hex_string_from_bitvector())
                #perform the substitution step
                substituted_R = self.substitute(expanded_R)
                #perform the permutation step
                permuted_R = substituted_R.permute(self.p_box)
                #XOR the permuted half with the left half
                new_R = permuted_R ^ L
                #the left half becomes the right half
                L = R
                #the right half becomes the new right half
                R = new_R
                # Print the intermediate results
                print("sbox sub:", substituted_R.get_hex_string_from_bitvector())
                print("pbox sub:", permuted_R.get_hex_string_from_bitvector())
                print("xored with left", new_R.get_hex_string_from_bitvector())
                print("Left Block:", L.get_hex_string_from_bitvector())
                print("Right Block:", R.get_hex_string_from_bitvector())

    # decrypt method declaration
    # inputs: message_file(str), outfile(str)
    # outputs: none
    # def decrypt(self, message_file, outfile):
    #     #decrypts the contents of the message file and writes the plaintext to the outfile

if __name__ == '__main__':
    cipher = DES(key=sys.argv[3])
    if sys.argv[1] == '-e':
        cipher.encrypt(message_file=sys.argv[2], outfile=sys.argv[4])
    # elif sys.argv[1] == '-d':
    #     cipher.decrypt(message_file=sys.argv[2], outfile=sys.argv[4])
#example usage:
#python3 DES.py -e message.txt key.txt encrypted.txt
#python3 DES.py -d encrypted.txt key.txt decrypted.txt