import string

# ALPHABET contains all ASCII letters (uppercase and lowercase), digits, punctuation, and space.
ALPHABET = string.ascii_letters + string.digits + string.punctuation + " "


def caesar_encrypt(plain_text, key):
    """
    Encrypts the given plain_text using the Caesar cipher algorithm.

    Args:
        plain_text (str): The message to be encrypted.
        key (int): The encryption key (number of positions to shift).

    Returns:
        str: The encrypted message (cipher_text).
    """
    # Initialize an empty string to store the encrypted message.
    cipher_text = ''

    # Loop through each character in the plain text.
    for char in plain_text:
        # Find the index of the character in the ALPHABET.
        char_index = ALPHABET.find(char)
        # Calculate the new index by shifting the current index by the key.
        char_index = (char_index + key) % len(ALPHABET)
        # Append the encrypted character to the cipher_text.
        cipher_text += ALPHABET[char_index]

    return cipher_text


def caesar_decrypt(cipher_text, key):
    """
    Decrypts the given cipher_text using the Caesar cipher algorithm.

    Args:
        cipher_text (str): The encrypted message to be decrypted.
        key (int): The decryption key (number of positions to shift back).

    Returns:
        str: The decrypted message (plain_text).
    """
    # Initialize an empty string to store the decrypted message.
    plain_text = ''

    # Loop through each character in the cipher text.
    for char in cipher_text:
        # Find the index of the character in the ALPHABET.
        char_index = ALPHABET.find(char)
        # Calculate the original index by shifting the current index backwards by the key.
        char_index = (char_index - key) % len(ALPHABET)
        # Append the decrypted character to the plain_text.
        plain_text += ALPHABET[char_index]

    return plain_text


def main():
    """
    Main function to run the Caesar cipher program.
    """
    # Prompt the user to enter a message to be encrypted.
    message = input("Enter message here to be encrypted: ")

    try:
        # Prompt the user to enter a numeric private key.
        private_key = int(input("Enter number for private key: "))

        # Encrypt the message using the Caesar cipher with the provided key.
        encrypted_message = caesar_encrypt(message, private_key)
        print(f"Encrypted Message: {encrypted_message}")

        # Decrypt the message to verify the encryption.
        decrypted_message = caesar_decrypt(encrypted_message, private_key)
        print(f"Decrypted Message: {decrypted_message}")

    except ValueError:
        # If the user does not enter a valid number, print an error message.
        print("Invalid input for private key. Please enter a number.")


if __name__ == "__main__":
    main()




