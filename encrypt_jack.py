import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

FOLDER = 'encrypt-elements'
PASSWORD = 'Abc123$%45'  # Change this or prompt for input
SALT = b'James-Salvatore'  # Should be random and stored for real use

def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len]) * pad_len

def encrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    plaintext = pad(plaintext)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)
    with open(filepath + '.enc', 'wb') as f:
        f.write(iv + ciphertext)
    os.remove(filepath)

def main():
    key = PBKDF2(PASSWORD, SALT, dkLen=32)
    folder_path = os.path.join(os.getcwd(), FOLDER)
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path) and not filename.endswith('.enc'):
            encrypt_file(file_path, key)
            print(f'Encrypted: {filename}')

if __name__ == '__main__':
    main()