import os
import pyotp
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode


def generate_and_endcrypt_secret_key(userpassword):
    """ Generating a secret key for OTP use"""
    if isinstance(userpassword, str):
        userpassword = userpassword.encode()
    secret_key = pyotp.random_base32()
    salt = os.urandom(16) # Generate a secure from the OS library which is randomly generated
    iv = os.urandom(16)
    """ Derive a cryptographic key from the userpassword """
    """
    1. Length: 32 bytes key fits the common key length that used for strong encryption algorithm like AES-256
    2. n: Cost factor, represent CPU/Memory cost
    3. r(Block SIze): Adjusting the value changes the memory usages pattern of the function
    4. p(Parallelization Factor): It allows to use multiple CPU/GPU taking advantages of highly powered core
    """
    kdf = Scrypt(salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(userpassword)
    """ Encrypt the secret key """
    """
    1. Initialize an AES cipher in CFB(Cipher FeedBack) mode with an 8-bit shift size, then turns a block cipher to stream cipher by modes.CFB8(os.urandom(16)
    2. Generates 16 bytes for each encryption session
    """
    cipher = Cipher(algorithms.AES(key), modes.CFB8(initialization_vector=iv), backend=default_backend())

    """
    Creates an encryption process object from the cipher configuration
    """
    encryptor = cipher.encryptor()

    """ This encrypts the secret key. secret_key.encode() converts the secret key into bytes suitable for encryption. The update method feeds the plaintext into 
    the cipher, and finalize completes the encryption process, ensuring that no plaintext is left unprocessed."""
    encrypted_secret_key = encryptor.update(secret_key.encode()) + encryptor.finalize()
    """ This encodes the raw binary data of the encrypted secret key into a format that can be safely stored in a text field in a database or
    transmitted over protocols that are not binary-safe."""
    return (urlsafe_b64encode(encrypted_secret_key), urlsafe_b64encode(iv), urlsafe_b64encode(salt), secret_key)




def decrypt_secret_key(encryptend_secret_key, userpassword, iv, salt):
    """ Decrypt the secret key """
    if isinstance(userpassword, str):
        userpassword = userpassword.encode()

    encryptend_secret_key = urlsafe_b64decode(encryptend_secret_key)
    iv = urlsafe_b64decode(iv)
    salt = urlsafe_b64decode(salt)

    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1, backend=default_backend())
    key = kdf.derive(userpassword)

    cipher = Cipher(algorithms.AES(key), modes.CFB8(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    secret_key = decryptor.update(encryptend_secret_key) + decryptor.finalize()
    secret_key = secret_key.decode()

    return secret_key


if __name__ == '__main__':
    encrypt = generate_and_endcrypt_secret_key('Shohan@')
    decrypt = decrypt_secret_key(encrypt[0], 'Shohan@', encrypt[1], encrypt[2])
    print(encrypt)
    print(decrypt)
