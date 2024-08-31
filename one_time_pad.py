import string
from secrets import randbelow

# ALPHABET contains all ASCII letters (both uppercase and lowercase), digits, punctuation, and space.
ALPHABET = string.ascii_letters + string.digits + string.punctuation + " "


def generate_random_key(text):
    """
    Generates a random key for one-time pad encryption.

    Args:
        text (str): The message for which to generate a key. The key length will match the message length.

    Returns:
        list: A list of random integers, each representing a shift amount corresponding to each character in the text.
    """
    # Initialize an empty list to store the random key.
    random_key = []

    # Generate a random integer for each character in the text.
    for _ in range(len(text)):
        random_key.append(randbelow(len(ALPHABET)))

    return random_key


def one_time_pad_encrypt(plain_text, key):
    """
    Encrypts the given plain_text using the one-time pad cipher algorithm.

    Args:
        plain_text (str): The message to be encrypted.
        key (list): A list of random integers used for the one-time pad encryption.

    Returns:
        str: The encrypted message (cipher_text).
    """
    # Initialize an empty string to store the encrypted message.
    cipher_text = ''

    # Loop through each character in the plain text along with its index.
    for index, char in enumerate(plain_text):
        # Get the corresponding key value for the current character.
        key_index = key[index]
        # Find the index of the character in the ALPHABET.
        char_index = ALPHABET.find(char)
        # Encrypt the character by shifting it using the key and add it to the cipher_text.
        cipher_text += ALPHABET[(char_index + key_index) % len(ALPHABET)]

    return cipher_text


def one_time_pad_decrypt(cipher_text, key):
    """
    Decrypts the given cipher_text using the one-time pad cipher algorithm.

    Args:
        cipher_text (str): The encrypted message to be decrypted.
        key (list): A list of random integers used for the one-time pad decryption.

    Returns:
        str: The decrypted message (plain_text).
    """
    # Initialize an empty string to store the decrypted message.
    plain_text = ''

    # Loop through each character in the cipher text along with its index.
    for index, char in enumerate(cipher_text):
        # Get the corresponding key value for the current character.
        key_index = key[index]
        # Find the index of the character in the ALPHABET.
        char_index = ALPHABET.find(char)
        # Decrypt the character by shifting it backwards using the key and add it to the plain_text.
        plain_text += ALPHABET[(char_index - key_index) % len(ALPHABET)]

    return plain_text


def main():
    """
    Main function to run the one-time pad cipher program.
    Asks the user for a message, generates a random key, then encrypts and decrypts the message using the key.
    """
    # Prompt the user to enter a message to be encrypted.
    message = input("Enter message to be encrypted: ")

    # Generate a random key for the message.
    private_key = generate_random_key(message)

    # Encrypt the message using the one-time pad cipher with the generated key.
    encrypted_message = one_time_pad_encrypt(message, private_key)

    # Decrypt the message using the one-time pad cipher with the same key.
    decrypted_message = one_time_pad_decrypt(encrypted_message, private_key)

    # Output the encrypted and decrypted messages.
    print(f"Encrypted message is: {encrypted_message}")
    print(f"Decrypted message is: {decrypted_message}")


if __name__ == "__main__":
    main()
