# IMPORTANT
This software is not error-free, data loss or security breach may occur.
Even if no data loss is found in the tests performed, caution must be exercised.

# VERSION
We're currently in the **1.0.0-BETA**. While I plan to make significant changes in the future, the main program will remain unchanged. For now, it functions flawlessly with its simple and straightforward (its just beta now, dont forget) interface.

# For exe Users
First, you need to open the settings.exe . Then, you'll see a data.json file created. This contains settings other than your password. You can change your preferences from the same exe file. enc.exe encrypts your files, dec.exe decrypts your files. Adjust your RAM usage according to your system, and if you're not familiar with coding or something else, it's best to stick with the default settings.

# The System
No data is saved in the system. Once your file is encrypted, it leaves no trace, and the .bin file it creates cannot be decrypted without your password. However, remember that your RAM usage during encryption must be the same as (or much) your RAM usage during decryption. For example, if it's encrypted with 2GB, it can be decrypted with >=2GB. If your password is simple, this encryption is meaningless. After encrypting the file, the main file didnt delete for the security of your data's.

# json File
This is checked in the settings.py/.exe section.

filename: Enter the name of the folder you will encrypt or you encrypted.

enc_filename: The name of the file that your encrypted file name like enc_filename.bin.

dec_filename: The name of the file created when your file is decrypted.

If you manually changed it and there is a problem, delete the file and open settings.py/.exe, a new JSON file will be created.

# Meaning of Ram Usage
There are huge differences between using 1 GB of RAM and 4 GB of RAM, but the main difference is this: Hashing with 1 GB of RAM is faster, but it is less secure in terms of security because decrypting can be done quickly, but when 4 GB of RAM is used, we have to wait a certain amount of time even while encrypting. 
Now, we'll see how long it takes to unlock encryption with 1GB of RAM and 4GB of RAM. Remember, this is a brute-force assumption because the system is built on your password.

# 1 GB
8.39 × 10^17 attempts / 20 attempts per sec
≈ 1.33 × 10^16 seconds
≈ 420 million years

# 4 GB
8.39 × 10^17 attempts / 1 attempt per sec
≈ 26.6 billion years
