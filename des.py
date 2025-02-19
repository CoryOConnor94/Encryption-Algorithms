from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import binascii
from Crypto.Random import get_random_bytes

# Size of private key must be 64 bits (8 bytes)
# User input can be hashed using SHA to transform key to 64 bits
key = b'mysecret'
encryption_cipher = DES.new(key, DES.MODE_CBC)

def des_encrypt(plain_text):
    # Pad plaintext to fit block size and encrypt
    cipher_text = encryption_cipher.encrypt(pad(plain_text, DES.block_size))
    # Return cipher text in ascii format rather than bytes
    return cipher_text


def des_decrypt(cipher_text):
    # Store iv used in encryption to variable for use in decryption
    iv = encryption_cipher.iv
    # Create cipher object for decryption with key and IV method and iv used in encryption
    decrypt_cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_message = decrypt_cipher.decrypt(cipher_text)
    decrypted_message = unpad(decrypted_message, DES.block_size)
    return decrypted_message


message = input("Enter message to be encrypted: ")
bytes_message = message.encode('UTF-8')
encrypted_message= des_encrypt(bytes_message)
print(binascii.hexlify(encrypted_message))
decrypted_message = des_decrypt(encrypted_message)
print(decrypted_message)
