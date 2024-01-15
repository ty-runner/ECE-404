from BitVector import *

def cryptBreak(ciphertextFile, key_bv):
    PassPhrase = "Hopes and dreams of a million years"
    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8

    bv_iv = BitVector(bitlist=[0]*BLOCKSIZE)
    for i in range(0, len(PassPhrase) // numbytes):
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
        bv_iv ^= BitVector(textstring=textstr)

    FILEIN = open(ciphertextFile)
    encrypted_bv = BitVector(hexstring=FILEIN.read())
    FILEIN.close()

    key_bv = BitVector(bitlist=[0]*BLOCKSIZE)
    previous_decrypted_block = bv_iv
    msg_decrypted_bv = BitVector(size=0)

    for i in range(0, len(encrypted_bv) // numbytes):
        bv = encrypted_bv[i*numbytes:(i+1)*numbytes]
        temp = bv.deep_copy()
        bv ^= previous_decrypted_block
        previous_decrypted_block = temp
        bv ^= key_bv
        msg_decrypted_bv += bv

    outputtext = msg_decrypted_bv.get_text_from_bitvector()
    return outputtext