import os
import sys
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

FOLDER = 'elements'
SALT = b'James-Salvatore'  # Must match the salt used for encryption
# PASSWORD IS Abc123$%45 for this file only .

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def decrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext)
    out_path = filepath[:-4]  # Remove .enc
    with open(out_path, 'wb') as f:
        f.write(plaintext)
    os.remove(filepath)
    print(f"Decrypted: {os.path.basename(out_path)}")

def main():
    password = input("Enter password to decrypt files: ").strip()
    key = PBKDF2(password, SALT, dkLen=32)
    if len(sys.argv) > 1:
        # Decrypt only the file provided as argument
        filepath = sys.argv[1]
        if os.path.isfile(filepath) and filepath.endswith('.enc'):
            try:
                decrypt_file(filepath, key)
            except Exception as e:
                print(f"Failed to decrypt {os.path.basename(filepath)}: {e}")
        else:
            print(f"File {filepath} is not a valid .enc file.")
    else:
        # Decrypt all .enc files in the folder
        folder_path = os.path.join(os.getcwd(), FOLDER)
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            if os.path.isfile(file_path) and filename.endswith('.enc'):
                try:
                    decrypt_file(file_path, key)
                except Exception as e:
                    print(f"Failed to decrypt {filename}: {e}")
        print("Decryption complete.")

if __name__ == '__main__':
    main()