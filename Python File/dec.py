import os
from getpass import getpass
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import tarfile
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
        memory_cost=Ram*1024*1024,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )

def decrypt_file(enc_file, output_folder, password):
    clear()
    print(Fore.BLUE + "Decrypting...")
    with open(enc_file, "rb") as f:
        blob = f.read()

    salt = blob[:16]
    nonce = blob[16:28]
    encrypted = blob[28:]

    key = derive_key(password, salt)
    aes = AESGCM(key)

    decrypted = aes.decrypt(nonce, encrypted, None)

    tmp_tar = "tmp_output.tar"
    with open(tmp_tar, "wb") as f:
        f.write(decrypted)

    with tarfile.open(tmp_tar, "r") as tar:
        tar.extractall(output_folder)

    os.remove(tmp_tar)
    clear()
    print(Fore.GREEN + "Decryption Completed →", output_folder)

if __name__ == "__main__":
    enc = cfg["enc_filename"]
    out = cfg["dec_filename"]
    pwd = getpass("Password: ")
    clear()
    decrypt_file(enc, out, pwd)
    print(Fore.RESET + "")
