from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

import base64

'''
    FUNCTION DECLARATION

    1) keyGenerator: Generate a valid DES3 24 bytes key using EDE
        Output: A valid DES3 24 bytes key
    2) saveKey: Save the key generated in a file in base 64
        Input: Name of the file and the key
    3) saveText: Save the encipher text in the file in base 64 with the extension .des
        Input: Name of the file and the encrypted message
    4) readMessage: Reads the text file
        Input: Name of the file with the text
        Output: The text of the file
    5) readText_base64: Read the text from a file in base 64 and decodes it
        Input: The name of the file to read
        Output: The text read
    6) read_ivText: 

    7) writeDecipherText: Write the decipher text in the file
        Input: The name of the file to write and the decipher text
'''

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
        plaintext_as_bytes = str.encode(plaintext)
        return plaintext_as_bytes

def saveText (textFile, iv, encrypted_message):
    # Save the encipher text in the file 
    
    with open(textFile, 'w') as f:
        if iv != "":
            base64Text = base64.b64encode(iv)
            f.write(str(base64Text, "utf-8"))
        base64Text=base64.b64encode(encrypted_message)
        f.write(str(base64Text, "utf-8"))

def readText_base64(keyFileDecipher):
    with open(keyFileDecipher, mode="r") as base64_file:
        data = base64.b64decode(bytes(base64_file.readline(), "utf-8"))
    return data

def read_ivText(fileText, mode):
    with open(fileText, mode="r") as base64_file:
        if mode == "CTR":
            iv = base64.b64decode(bytes(base64_file.readline(12), "utf-8"))#12 CTR MODE 
        else:
            iv = base64.b64decode(bytes(base64_file.readline(24), "utf-8"))
        
        data = base64.b64decode(bytes(base64_file.readline(), "utf-8"))
        
    return iv,data

def writeDecipherText(textName: str, decriptedText: bytes):
    with open(textName, mode="w", encoding="utf-8") as wfile:
        wfile.write(str(decriptedText,"utf-8"))

'''
    MAIN PART
        Input:  the option to encrypt or decrypt a text
                the option to choose the operation mode to decrypt
        Output: Files with the key in base64, encrypted text in the diferent operation modes
                in base64 and after the decryption a text generates a file with the original text. 
'''

option=input("Select one option: \n1. Encryption \n2. Decryption\n")

if option == '1':
    plaintext_File=input("Write the name of the file with the plaintext with te extension, for example: plaintext.txt\n")
    plaintext=readMessage(plaintext_File)

    key_128 = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    key_192 = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17'
    key_256 = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
    #key_128 = keyGenerator(16)
    #key_192 = keyGenerator(24)
    #key_256 = keyGenerator(32)
    #print(f"Bytes del 128: {len(key_128)}")
    #print(f"Bytes del 192: {len(key_192)}")
    #print(f"Bytes del 256: {len(key_256)}")

    #Cipher modes
    cipher_CBC = AES.new(key_128, AES.MODE_CBC)
    cipher_CTR = AES.new(key_192, AES.MODE_CTR)
    cipher_CFB = AES.new(key_256, AES.MODE_CFB)

    #Nonce creator
    nonce = cipher_CTR.nonce
    

    #Encryption part
    #CBC
    ciphered_data_CBC = cipher_CBC.encrypt(pad(plaintext, AES.block_size))
    print(f"Texto cifrado: {str(ciphered_data_CBC)}")
    saveText("encryptedCBC.txt", cipher_CBC.iv, ciphered_data_CBC)
    saveKey("CBCKey.txt",key_128)
    print(f"CBC_iv={cipher_CBC.iv}\n")
    #CTR
    ciphered_data_CTR = cipher_CTR.encrypt(plaintext)
    saveText("encryptedCTR.txt",nonce, ciphered_data_CTR)#CTR dont have iv :cipher_CTR.iv
    saveKey("CTRKey.txt",key_192)
    #CFB
    ciphered_data_CFB = cipher_CFB.encrypt(plaintext)
    saveText("encryptedCFB.txt", cipher_CFB.iv, ciphered_data_CFB)
    saveKey("CFBKey.txt",key_256)

else:
    optionD=input("Select an option:\n1. CBC Mode\n2.CTR Mode\n3.CFB Mode\n")
    if (optionD == '1'):

        encipherFileCBC=input("Write the name of the file with the CBC cipher text with extension:\n")
        keyFile=input("Write the name of the file with the key of 128 bits with extension\n")
        #Read the files
        key = readText_base64(keyFile)
        iv, ciphertext= read_ivText(encipherFileCBC,"CBC")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)  # Setup cipher
        original_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        writeDecipherText("originalCBC.txt", original_data)
        print(f"Proceso Terminado")
    elif (optionD == '2'):
        encipherFileCTR=input("Write the name of the file with the CTR cipher text with extension:\n")
        keyFile=input("Write the name of the file with the key of 192 bits with extension\n")
        #Read the files
        key = readText_base64(keyFile)
        
        nonce, ciphertext= read_ivText(encipherFileCTR,"CTR")
        cipher = AES.new(key, AES.MODE_CTR, nonce = nonce)  # Setup cipher
        original_data = cipher.decrypt(ciphertext)
        writeDecipherText("originalCTR.txt", original_data)
        print(f"Proceso Terminado")
    elif (optionD == '3'):
        encipherFileCFB=input("Write the name of the file with the CFB cipher text with extension:\n")
        keyFile=input("Write the name of the file with the key of 256 bits with extension\n")
        #Read the files
        key = readText_base64(keyFile)
        iv, ciphertext= read_ivText(encipherFileCFB,"CFB")
        cipher = AES.new(key, AES.MODE_CFB, iv=iv)  # Setup cipher
        original_data = cipher.decrypt(ciphertext)
        writeDecipherText("originalCFB.txt", original_data)
        print(f"Proceso Terminado")