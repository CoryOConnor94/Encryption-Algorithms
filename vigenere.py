import string

# ALPHABET contains all ASCII letters (both uppercase and lowercase), digits, punctuation, and space.
ALPHABET = string.ascii_letters + string.digits + string.punctuation + " "


def vigenere_encrypt(plain_text, key):
    """
    Encrypts the given plain_text using the Vigenère cipher algorithm.

    Args:
        plain_text (str): The message to be encrypted.
        key (str): The encryption key, a sequence of characters to be used cyclically.

    Returns:
        str: The encrypted message (cipher_text).
    """
    # Initialize an empty string to store the encrypted message.
    cipher_text = ''
    # Index to track the position in the key.
    key_index = 0

    # Loop through each character in the plain text.
    for char in plain_text:
        # Find the index of the current character and corresponding key character in the ALPHABET.
        char_index = (ALPHABET.find(char) + ALPHABET.find(key[key_index])) % len(ALPHABET)
        # Append the encrypted character to the cipher_text.
        cipher_text += ALPHABET[char_index]
        # Move to the next character in the key.
        key_index += 1

        # If the end of the key is reached, reset the key index to start again.
        if key_index == len(key):
            key_index = 0

    return cipher_text


def vigenere_decrypt(cipher_text, key):
    """
    Decrypts the given cipher_text using the Vigenère cipher algorithm.

    Args:
        cipher_text (str): The encrypted message to be decrypted.
        key (str): The decryption key, a sequence of characters to be used cyclically.

    Returns:
        str: The decrypted message (plain_text).
    """
    # Initialize an empty string to store the decrypted message.
    plain_text = ''
    # Index to track the position in the key.
    key_index = 0

    # Loop through each character in the cipher text.
    for char in cipher_text:
        # Find the index of the current character and corresponding key character in the ALPHABET.
        char_index = (ALPHABET.find(char) - ALPHABET.find(key[key_index])) % len(ALPHABET)
        # Append the decrypted character to the plain_text.
        plain_text += ALPHABET[char_index]
        # Move to the next character in the key.
        key_index += 1

        # If the end of the key is reached, reset the key index to start again.
        if key_index == len(key):
            key_index = 0

    return plain_text


def main():
    """
    Main function to run the Vigenère cipher program.
    Asks the user for a message and a key, then encrypts and decrypts the message using the provided key.
    """
    # Prompt the user to enter a message to be encrypted.
    message = input("Enter message to be encrypted: ")
    # Prompt the user to enter a key for encryption/decryption.
    private_key = input("Enter private key: ")

    # Encrypt the message using the Vigenère cipher with the provided key.
    encrypted_message = vigenere_encrypt(message, private_key)
    # Output the encrypted message.
    print(f"Encrypted Message: {encrypted_message}")

    # Decrypt the message using the Vigenère cipher with the same key.
    decrypted_message = vigenere_decrypt(encrypted_message, private_key)
    # Output the decrypted message.
    print(f"Decrypted Message: {decrypted_message}")


if __name__ == "__main__":
    main()

