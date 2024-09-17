from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import binascii
from Crypto.Random import get_random_bytes

# Size of private key must be 64 bits (8 bytes)
# User input can be hashed using SHA to transform key to 64 bits

key = b'mysecret'

# Create cipher object for encryption with private key and IV method
encryption_cipher = DES.new(key, DES.MODE_CBC)
# Print IV of object
print(encryption_cipher.IV)
# Print Block size
print(encryption_cipher.block_size)

plaintext = b'This is a message'
# Pad plaintext to fit block size and encrypt
cipher_text = encryption_cipher.encrypt(pad(plaintext, DES.block_size))
# Display cipher text in ascii format rather than bytes
print(binascii.hexlify(cipher_text))


# Store iv used in encryption to variable for use in decryption
iv = encryption_cipher.iv
# Create cipher object for decryption with key and IV method and iv used in encryption
decrypt_cipher = DES.new(key, DES.MODE_CBC, iv)
decrypted_message = decrypt_cipher.decrypt(cipher_text)
decrypted_message = unpad(decrypted_message, DES.block_size)
print(decrypted_message)