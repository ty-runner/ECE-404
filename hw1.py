from BitVector import *

def key_from_passphrase(passphrase, key_size):
    # Generate a key using the passphrase
    key = BitVector(textstring=passphrase)
    while key.length() < key_size:
        key += key  # Repeat the key until it reaches the desired length
    return key

def cryptBreak(encrypted_file, passphrase):
    BLOCKSIZE = 16

    # Read the encrypted file
    with open(encrypted_file, 'r') as file:
        encrypted_text = file.read()

    # Create a BitVector from the encrypted text
    encrypted_bv = BitVector(hexstring=encrypted_text)

    # Brute-force attack to decrypt the message
    for key in range(2 ** BLOCKSIZE):  # Keyspace size is 2^BLOCKSIZE
        key_bv = key_from_passphrase(passphrase, BLOCKSIZE)
        decrypted_bv = encrypted_bv ^ key_bv

        # Check if the decrypted message contains the word 'Ferrari'
        decrypted_message = decrypted_bv.get_text_from_bitvector()
        if 'Ferrari' in decrypted_message:
            return decrypted_message, key_bv

    return "Decryption failed", None

# Example usage
passphrase = "Hopes and dreams of a million years"
decryptedMessage, key_bv = cryptBreak('cipherText.txt', passphrase)

if 'Ferrari' in decryptedMessage:
    print('Encryption Broken!')
    print('Decrypted Message:', decryptedMessage)
    print('Encryption Key:', key_bv)
else:
    print('Not decrypted yet')
