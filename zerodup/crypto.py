from . import bigbuffer
from . import constants
from . import exceptions

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
import hashlib


def sha256_hash(stream):
    hasher = hashlib.sha256()
    while chunk := stream.read(constants.STREAM_CHUNK_SIZE):
        hasher.update(chunk)
    return hasher.digest()


def aes_ctr_encrypt(cleartext_stream, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    cleartext_stream.seek(0)
    ciphertext_stream = bigbuffer.BigBuffer()
    while chunk := cleartext_stream.read(constants.STREAM_CHUNK_SIZE):
        ciphertext_stream.write(encryptor.update(chunk))
    ciphertext_stream.write(encryptor.finalize())
    ciphertext_stream.seek(0)
    return ciphertext_stream


def aes_ctr_decrypt(ciphertext_stream, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    cleartext_stream = bigbuffer.BigBuffer()
    try:
        while chunk := ciphertext_stream.read(constants.STREAM_CHUNK_SIZE):
            cleartext_stream.write(decryptor.update(chunk))
        cleartext_stream.write(decryptor.finalize())
    except ValueError as err:
        cleartext_stream.close()
        raise exceptions.CorruptedData() from err
    cleartext_stream.seek(0)
    return cleartext_stream
