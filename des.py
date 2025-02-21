from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import binascii

def derive_des_key(user_input):
    """Derive a secure 8-byte DES key from user input using SHA-256."""
    hashed_key = SHA256.new(user_input.encode()).digest()  # 32-byte hash
    return hashed_key[:8]  # Use first 8 bytes (64 bits) for DES key

def des_encrypt(plain_text, key):
    """Encrypt the given plaintext using DES in CBC mode."""
    iv = get_random_bytes(8)  # Generate a new random IV for each encryption
    cipher = DES.new(key, DES.MODE_CBC, iv)  # Create cipher object
    cipher_text = cipher.encrypt(pad(plain_text, DES.block_size))
    encrypted_data = iv + cipher_text  # Prepend IV to ciphertext for later decryption
    return binascii.hexlify(encrypted_data).decode()  # Convert to hex string

def des_decrypt(encrypted_hex, key):
    """Decrypt the given ciphertext using DES in CBC mode."""
    encrypted_data = binascii.unhexlify(encrypted_hex)  # Convert hex string back to bytes
    iv, cipher_text = encrypted_data[:8], encrypted_data[8:]  # Extract IV
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(cipher_text), DES.block_size)
    return decrypted_message

def main():
    """ Main flow of program"""
    # Get user input and derive a secure DES key
    user_password = input("Enter password to derive key: ")
    key = derive_des_key(user_password)  # Generate a secure 8-byte DES key

    # Encrypt the message
    message = input("Enter message to be encrypted: ")
    bytes_message = message.encode('UTF-8')
    encrypted_message = des_encrypt(bytes_message, key)

    print("Encrypted message: ", encrypted_message)

    # Decrypt the message
    decrypted_message = des_decrypt(encrypted_message, key)
    print("Decrypted:", decrypted_message.decode('UTF-8'))

if __name__ == '__main__':
    main()
