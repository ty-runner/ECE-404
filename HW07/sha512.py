from BitVector import *

# hash the ASCII in input.txt and write the resulting message digest to hashed.txt
# write to hashed.txt as hexstring format

def sha512(input_file, output_file):
    # read the input file
    bv = BitVector(filename = input_file)
    # create a BitVector object from the input file
    bv = BitVector(textstring = bv.get_bitvector_in_ascii())
    # get the length of the input file
    length = bv.length()
    # get the number of bits in the input file
    bv1 = bv + BitVector(bitstring="1")
    # append a single bit with value 1 to the end of the input bit vector
    length1 = bv1.length()
    # get the length of the bit vector before appending the single bit
    howmanyzeros = (896 - length1) % 1024
    # calculate the number of zeros to append to the bit vector
    zerobits = BitVector(size = howmanyzeros)
    # create a bit vector of zeros
    bv1 += zerobits
    # append the zero bit vector to the input bit vector
    bv2 = BitVector(intVal = length, size = 128)
    # create a 128-bit vector from the length of the original input bit vector
    bv3 = bv2.deep_copy()
    # create a deep copy of the 128-bit vector
    bv4 = BitVector(intVal = length1, size = 128)
    # create a 128-bit vector from the length of the input bit vector after appending the single bit
    bv5 = bv4.deep_copy()
    # create a deep copy of the 128-bit vector
    message = bv + bv1 + bv2 + bv3 + bv4 + bv5
    # concatenate the input bit vector, the single bit, the zero bit vector, and the two 128-bit vectors
    words = [0] * 80
    # create a list of 80 elements, all initialized to 0
    for n in range(0, message.length(), 1024):
        # iterate through the message bit vector in 1024-bit increments
        block = message[n:n+1024]
        # get the 1024-bit block
        words[0:16] = [block[i:i+64] for i in range(0, 1024, 64)]
        # get the 16 64-bit words from the 1024-bit block
        for i in range(16, 80):
            # iterate through the 16 64-bit words
            word = words[i-16] ^ words[i-15] ^ words[i-14] ^ words[i-13]
            # calculate the word
            words[i] = word << 1 | word >> 63
            # calculate the word




#usability: python sha512.py input.txt hashed.txt