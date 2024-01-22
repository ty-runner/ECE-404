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

    #encrypt method declaration
    #inputs: message_file(str), outfile(str)
    #outputs: none
    def encrypt(self, message_file, outfile):
        #encrypts the contents of the message file and writes the ciphertext to the outfile

    # decrypt method declaration
    # inputs: message_file(str), outfile(str)
    # outputs: none
    def decrypt(self, message_file, outfile):
        #decrypts the contents of the message file and writes the plaintext to the outfile

#example usage:
#python3 DES.py -e message.txt key.txt encrypted.txt
#python3 DES.py -d encrypted.txt key.txt decrypted.txt