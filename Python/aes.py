from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

import base64

def keyGenerator(n):
    #Generate a valid AES 128, 192 or 256 bits key 
    key = get_random_bytes(n)
    return key

def saveKey (keyFile, key):
    with open(keyFile , 'w') as f:
        base64TextKey=base64.b64encode(key)
        f.write(str(base64TextKey, "utf-8"))

def readMessage(textFile):
    with open(textFile ,'r', encoding="utf-8" ) as r:
        plaintext=r.read()
        return plaintext

def saveText (textFile, iv, encrypted_message):
    # Save the encipher text in the file 
    
    with open(textFile, 'w') as f:
        base64Text=base64.b64encode(encrypted_message)
        f.write(str(base64Text, "utf-8"))

def readText_base64(keyFileDecipher):
    with open(keyFileDecipher, mode="r") as base64_file:
        data = base64.b64decode(bytes(base64_file.readline(), "utf-8"))
    return data

def read_ivText(fileText):
    with open(fileText, mode="r") as base64_file:
        iv = base64.b64decode(bytes(base64_file.readline(16), "utf-8"))
        data = base64.b64decode(bytes(base64_file.readline(), "utf-8"))
    return iv,data

def writeDecipherText(textName: str, decriptedText: bytes):
    with open(textName, mode="w", encoding="utf-8") as wfile:
        wfile.write(str(decriptedText,"utf-8"))


option=input("Select one option: \n1. Encryption \n2. Decryption\n")

if option == '1':
    plaintext_File=input("Write the name of the file with the plaintext with te extension, for example: plaintext.txt\n")
    plaintext=readMessage(plaintext_File)
    key_128 = keyGenerator(16)
    key_192 = keyGenerator(24)
    key_256 = keyGenerator(32)

    #Cipher modes
    cipher_CBC = AES.new(key_128, AES.MODE_CBC)
    cipher_CTR = AES.new(key_192, AES.MODE_CTR)
    cipher_CFB = AES.new(key_256, AES.MODE_CFB)

    #Nonce creator
    nonce = cipher_CTR.nonce
    #nonce = cipher_CFB.nonce

    #Encryption part
    #CBC
    ciphered_data_CBC = cipher_CBC.encrypt(pad(plaintext, AES.block_size))
    saveText("encryptedCBC.txt", cipher_CBC.iv, ciphered_data_CBC)
    #CTR
    ciphered_data_CTR = cipher_CTR.encrypt(plaintext)
    saveText("encryptedCTR.txt", cipher_CTR.iv, ciphered_data_CTR)
    #CFB
    ciphered_data_CFB = cipher_CFB.encrypt(plaintext)
    saveText("encryptedCFB.txt", cipher_CFB.iv, ciphered_data_CFB)

else:
    optionD=input("Select an option:\n1. CBC Mode\n2.CTR Mode\n3.CFB Mode\n")
    if (optionD == 1):

        encipherFileCBC=input("Write the name of the file with the CBC cipher text with extension:\n")
        keyFile=input("Write the name of the file with the key of 128 bits with extension\n")
        #Read the files
        key = readText_base64(keyFile)
        iv, ciphertext= read_ivText(encipherFileCBC)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)  # Setup cipher
        original_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        writeDecipherText("originalCBC.txt", original_data)
        print(f"Proceso Terminado")
    elif (optionD == 2):
        encipherFileCTR=input("Write the name of the file with the CBC cipher text with extension:\n")
        keyFile=input("Write the name of the file with the key of 192 bits with extension\n")
        #Read the files
        key = readText_base64(keyFile)
        iv, ciphertext= read_ivText(encipherFileCTR)
        cipher = AES.new(key, AES.MODE_CTR, iv=iv)  # Setup cipher
        original_data = cipher.decrypt(ciphertext)
        writeDecipherText("originalCTR.txt", original_data)
        print(f"Proceso Terminado")
    else:
        encipherFileCFB=input("Write the name of the file with the CBC cipher text with extension:\n")
        keyFile=input("Write the name of the file with the key of 256 bits with extension\n")
        #Read the files
        key = readText_base64(keyFile)
        iv, ciphertext= read_ivText(encipherFileCFB)
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)  # Setup cipher
        original_data = cipher.decrypt(ciphertext)
        writeDecipherText("originalCBC.txt", original_data)
        print(f"Proceso Terminado")