# Encryption Scripts

## Overview
This repository contains multiple encryption and decryption scripts for different ciphers, including:

- **Caesar Cipher** (Encryption, Decryption, and Brute Force Attack)
- **Vigenère Cipher** (Encryption and Decryption)
- **DES Encryption** *(To be implemented)*
- **AES Encryption** *(To be implemented)*

Each script allows the user to encrypt and decrypt messages using a specific cipher, with interactive user input.

---

## Scripts

### 1. **Caesar Cipher**
#### **Description**
The Caesar cipher is a simple substitution cipher that shifts each letter in the plaintext by a fixed number of positions in the alphabet.

#### **Files**
- `caesar_cipher.py`: Implements encryption and decryption.
- `brute_force_caesar.py`: Attempts to brute-force decrypt a Caesar cipher message by trying all possible shifts.

#### **Usage**
Run the script and enter a message along with a numerical key:
```bash
python caesar_cipher.py
```
Example interaction:
```
Enter message here to be encrypted: hello
Enter number for private key: 3
Encrypted Message: khoor
Decrypted Message: hello
```

For brute-force decryption, run:
```bash
python brute_force_caesar.py
```
Example:
```
Enter the cipher text to be cracked: khoor
With 3, the result is: hello
```
#### Requirements
Ensure you have the required dependencies installed:
```bash
pip install nltk
```
For the first time running `brute_force_caesar.py`, ensure the NLTK word list is downloaded:
```python
import nltk
nltk.download('words')
```
---

### 2. **Vigenère Cipher**
#### **Description**
The Vigenère cipher is a polyalphabetic substitution cipher that uses a keyword to determine shifts for each letter.

#### **File**
- `vigenere_cipher.py`: Implements encryption and decryption.


#### **Usage**
Run the script and provide a message and key:
```bash
python vigenere_cipher.py
```
Example:
```
Enter message to be encrypted: hello
Enter private key: key
Encrypted Message: riijm
Decrypted Message: hello
```

---

### 3. **DES Encryption**
#### **Description**
The Data Encryption Standard (DES) is a symmetric-key algorithm for encrypting digital data.

#### **File**
- `des_cipher.py` Implements encryption and decryption

#### Requirements
Ensure you have the required dependencies installed:
```bash
pip install pycryptodome
```

#### **Usage**
Run the script and provide a message and key:
```bash
python des.py
```
Example:
```
Enter password to derive key: secretkey
Enter message to be encrypted: hello
Encrypted Message: riijm
Decrypted Message: hello
```

---

### 4. **AES Encryption**
#### **Description**
This script provides a secure way to encrypt and decrypt messages using AES-256 in CBC mode.
Derives a cryptographic key from a user-provided password using PBKDF2 and ensures security with a unique salt and IV for each encryption operation.

#### **File**
- `aes.py` Implements encryption and decryption

#### Requirements
Ensure you have the required dependencies installed:
```bash
pip install pycryptodome
```

#### **Usage**
```bash
python aes_script.py
```

#### **Example**
Encryption:
```bash
Enter password: mysecurepassword
Enter message to encrypt: Hello, world!
```
Decryption:
```bash
Enter password: mysecurepassword
Decrypted message: Hello, world!
```

#### **Security Considerations**
- The script does not store passwords – ensure you remember yours!
- PBKDF2 with 100,000 iterations provides strong key derivation.
- Always store the full encrypted output (including salt and IV) to allow successful decryption.

---

## License
This project is released under the MIT License.

