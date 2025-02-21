import string
import nltk
from nltk.corpus import words

# Ensure the words dataset is downloaded
try:
    ENGLISH_WORDS = set(words.words())
except LookupError:
    print("Downloading NLTK word list...")
    nltk.download('words')
    ENGLISH_WORDS = set(words.words())

# ALPHABET contains all ASCII letters (uppercase and lowercase), digits, punctuation, and space.
ALPHABET = string.ascii_letters + string.digits + string.punctuation + " "


def brute_force_caesar(cipher_text):
    """
    Brute forces the given cipher_text using each possible key in alphabet.

    Args:
        cipher_text (str): The encrypted message to be decrypted.

    Returns:
        str: The decrypted message (plain_text).
    """

    # Try all possible key values in alphabet
    for key in range(len(ALPHABET)):
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

        # Check if result contains english words
        if meaningful_words(plain_text):
            print(f'With {key}, the result is: {plain_text}')  # Print only meaningful results


def meaningful_words(text):
    """
    Takes results of brute force and checks against known words

    Returns:
        bool: True if the plaintext contains at least one English word bigger than 2 letters

    """
    return any(word in text.lower() for word in ENGLISH_WORDS if len(word) > 3)     # Ignore 3 letter or less words


def main():
    """Main flow of program, takes in cipher text from user"""
    cipher_text = input("Enter the cipher text to be cracked: ")
    brute_force_caesar(cipher_text)


if __name__ == '__main__':
    main()
