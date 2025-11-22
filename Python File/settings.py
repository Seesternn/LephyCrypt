import json
import psutil
import json
import os
from time import sleep
from colorama import init, Fore, Back, Style
import os

ram_bytes = psutil.virtual_memory().total
ram_gb = ram_bytes / (1024 ** 3)  # GB
ram_str = float(int(ram_gb))


def clear():
    os.system("cls" if os.name == "nt" else "clear")


init()
clear()

print(Fore.GREEN + """
    filename: Your file's name for encryption.
    enc_filename: Your file's name for encrypted.
    dec_filename: Your file's name for after decrypted.
    ram: The amount of RAM required for encryption and decryption. (Used only during the process)
""")
sleep(3)
clear()

print(Fore.RED + """
    DO NOT EXCEED THE RECOMMENDED AMOUNT OF RAM!!
""")
sleep(2)
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


def save_config(data, path="data.json"):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def update_values(cfg, filename=None, ram=None, enc_filename=None, dec_filename=None):
    if filename:
        cfg["filename"] = filename

    if ram:
        cfg["ram"] = int(ram)

    if enc_filename:
        cfg["enc_filename"] = enc_filename

    if dec_filename:
        cfg["dec_filename"] = dec_filename

    return cfg


print(Style.RESET_ALL + """
    Which data do you want to change?
    Your Data:
""")
print(Fore.RED + "  ---- JSON CONFIG ----")
for key, value in cfg.items():
    print("    " + Fore.YELLOW + f"{key}: {value}")
print(Style.RESET_ALL + """
    For Change:
    1: filename
    2: enc_filename
    3: dec_filename
    4: ram
    
    for example: filename + ram = 14 or filename + enc_filename + ram = 124
    """)
change = str(input("""  ##>"""))
clear()

if "1" in change:
    print("    Write Your File Name:")
    filename = input("  ##>")

else:
    filename = cfg["filename"]

clear()

if "2" in change:
    print("    Write Your Encrypted File Name:")
    enc_filename = input("  ##>") + ".bin"
else:
    enc_filename = cfg["enc_filename"]

clear()

if "3" in change:
    print("    Write Your Decrypted File Name:")
    dec_filename = input("  ##>")
else:
    dec_filename = cfg["dec_filename"]

clear()

if "4" in change:
    print("    Your Total RAM: ", ram_gb, " GB")
    print("")
    if float(ram_str) > 17:
        print(Fore.RED + "    You Can Use 8<= GB Ram.")
        maxusage = 8
    if 17 > float(ram_str) > 14:
        print(Fore.RED + "    You Can Use 4<= GB Ram.")
        maxusage = 4
    if 6 < float(ram_str) < 15:
        print(Fore.RED + "    You Can Use 2<= GB Ram.")
    if float(ram_str) < 6.4:
        print(Fore.RED + "    You Can Use 1<= GB Ram.")



    print("")
    print("    " + Style.RESET_ALL + " Write Your RAM usage:")
    ram = int(input("  ##>"))
    if ram > maxusage:
        clear()
        print(Fore.RED + """
        This Ram usage is too much for your PC.
        We want you to be careful and know that it is your responsibility.
        If you give up, you have 10 seconds to close the app.
        Then it will save.
        """)
        sleep(10)
    clear()


else:
    ram = str(cfg["ram"])

cfg = update_values(cfg, filename=filename, enc_filename=enc_filename, dec_filename=dec_filename, ram=ram)
save_config(cfg)
print(Fore.GREEN + """
Saved!""")
input("Press enter to close...")


