# Immortal-Files

Solid file-by-file backup utility. Make an exact clone of your disk in full or back up specified documents (or folders) only. Keep all your data safe off site (on remote servers) and on site (on external drives). Create a bootable copy of your computer’s operating system and applications to protect your data if your computer is stolen or damaged. Back up to an Google Drive, FTP, SFTP, WebDAV, or OpenStack Swift remote server. Store your files in different locations to reduce the risks of fire, flood, and power outages. http://www.immortalfiles.com

# Encryption

Immortal Files uses the AES256 algorithm, which provides extremely strong security. To encrypt the data, Immortal Files generates an encryption key, which is based on a password you create.

Every file is encrypted separately, and in the event of damage to your backup storage device, you can restore the data.

Every file is split to 50MB chunks, and every file or chunk is encrypted using a new initialization vector (IV), which provides increased security.

Emergency decryption utility located in decrypter folder. 
To compile it run "clang++ main.cpp -o decrypter -lcrypto -lssl" command

To decrypt file run ./decrypter "MyPassword" "Input File Path" "Output File Path". 


