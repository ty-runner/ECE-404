from BitVector import *

def cryptBreak(encrypted_file, key_bv):
    # Read the encrypted file
    with open(encrypted_file, 'r') as file:
        encrypted_text = file.read()

    # Create a BitVector from the encrypted text
    encrypted_bv = BitVector(hexstring=encrypted_text)

    # Brute-force attack to decrypt the message
    for key in range(2**16):  # Keyspace size is 2^16 for a 16-bit key
        key_bv = BitVector(intVal=key, size=16)
        decrypted_bv = encrypted_bv ^ key_bv

        # Check if the decrypted message contains the word 'Ferrari'
        decrypted_message = decrypted_bv.get_text_from_bitvector()
        print(key_bv, decrypted_message)
        if 'Ferrari' in decrypted_message:
            return decrypted_message

    return "Decryption failed"

# Example usage
RandomInteger = 9999  # Arbitrary integer for creating a BV
key_bv = BitVector(intVal=RandomInteger, size=16)
decryptedMessage = cryptBreak('cipherText.txt', key_bv)

if 'Ferrari' in decryptedMessage:
    print('Encryption Broken!')
else:
    print('Not decrypted yet')
