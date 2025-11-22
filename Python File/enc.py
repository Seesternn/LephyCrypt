import os
import tarfile
from getpass import getpass
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from colorama import init, Fore, Back, Style
import json

def clear():
    os.system("cls" if os.name == "nt" else "clear")
clear()
def load_config(path="data.json"):
    if not os.path.exists(path):
        default_cfg = {
            "filename": "",
            "enc_filename": "",
            "dec_filename": "",
            "ram": 2
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default_cfg, f, indent=4, ensure_ascii=False)
        return default_cfg


    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


cfg = load_config()
Ram = int(cfg["ram"])

def derive_key(password: str, salt: bytes):
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=6,
        memory_cost=Ram*1024*1024,  # 1 GB
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )

def encrypt_folder(folder_path, output_file, password):
    print(Fore.BLUE + "Encrypting...")
    # 1) klasörü .tar olarak paketle
    tar_path = output_file + ".tmp"
    with tarfile.open(tar_path, "w") as tar:
        tar.add(folder_path, arcname=os.path.basename(folder_path))

    # 2) anahtar üret
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)

    # 3) dosyayı oku, şifrele
    with open(tar_path, "rb") as f:
        data = f.read()

    encrypted = aes.encrypt(nonce, data, None)

    # 4) çıktı dosyasına salt + nonce + encrypted yaz
    with open(output_file, "wb") as f:
        f.write(salt + nonce + encrypted)

    os.remove(tar_path)
    print(Fore.RESET + "")
    clear()
    print(Fore.GREEN + "Encryption Done →", output_file)

if __name__ == "__main__":
    folder = cfg["filename"]
    out = cfg["enc_filename"]

    pwd = getpass("Password: ")
    clear()
    encrypt_folder(folder, out, pwd)
    print(Fore.RESET + "")
