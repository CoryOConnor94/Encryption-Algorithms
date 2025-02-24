from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
import binascii


def derive_key(password, salt, iterations=100000):
    """Derives a 32-byte (256-bit) key using PBKDF2 with 100000 iterations and 16 byte salt to ensure secure unique key"""
    return PBKDF2(password, salt, dkLen=32, count=iterations)

def aes_encrypt(plain_text, password):
    """Encrypts message using AES-256 in CBC mode """
    salt = get_random_bytes(16) # Generate random 16 byte salt
    private_key = derive_key(password, salt) # Derive private key from password and salt

    iv = get_random_bytes(16)  # Generate random 16 byte Initialization vector
    encrypt_cipher = AES.new(private_key, AES.MODE_CBC, iv)   # Create cipher object for encryption

    encrypted_data = encrypt_cipher.encrypt(pad(plain_text.encode(), AES.block_size))   # Encode UTF-8 into bytes for encryption
    return binascii.hexlify(salt + iv + encrypted_data) # Store salt, iv and ciphertext together to simplify decryption


def aes_decrypt(encrypted_data, password):
    cipher_text = binascii.unhexlify(encrypted_data) # Convert hex to bytes for decryption

    salt = cipher_text[:16]     # Extract Salt
    iv = cipher_text[16:32]     # Extract IV
    encrypted_message = cipher_text[32:]   # Extract encrypted message

    private_key = derive_key(password, salt)    # Recompute private key from password and salt
    decrypt_cipher = AES.new(private_key, AES.MODE_CBC, iv)   # Create cipher object for decryption

    decrypted_data = unpad(decrypt_cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_data.decode()


def main():
    """Main function controlling flow of program"""
    password = input('Enter a password: ')
    message = input('Enter a message: ')

    encrypted_message = aes_encrypt(message, password)
    print(f'Encrypted message: {encrypted_message.decode("UTF-8")}')

    decrypted_message = aes_decrypt(encrypted_message, password)
    print(f'Decrypted message: {decrypted_message}')

if __name__ == '__main__':
    main()