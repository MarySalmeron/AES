from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import math
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


option=input("Select one option: \n1. Encryption \n2. Decryption")

if option == '1':
    plaintext_File=input("Write the name of the file with the plaintext with te extension, for example: plaintext.txt")
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

    #CTR
    ciphertext, tag = cipher.encrypt_and_digest(data)

    #CFB
    ciphered_data_CFB = cipher.encrypt(plaintext)