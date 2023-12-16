import boto3  # Import the AWS SDK for Python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Import AES-GCM for decryption
import base64  # For base64 decoding of the encrypted key
import time  # Module for measuring execution time

def getUserInputForDecryption():
    """
    This function prompts the user to enter the path of the encrypted file that they want to decrypt.
    It returns the entered file path for further processing.
    """
    inputEncryptedFile = input("Enter the path of the encrypted file to decrypt: ")
    return inputEncryptedFile  # Return the entered file path

def decryptData(ciphertext, nonce, encryptedKey, kmsClient):
    """
    This function decrypts the encrypted data.
    It takes the ciphertext, nonce, encrypted data key, and a KMS client as inputs.
    First, it uses the KMS client to decrypt the encrypted data key.
    Then, it uses the decrypted key and the nonce to decrypt the ciphertext using AES-GCM.
    It returns the decrypted plaintext data.
    """
    response = kmsClient.decrypt(CiphertextBlob=encryptedKey)
    plaintextKey = response['Plaintext']  # Retrieve the plaintext version of the data key

    aesgcm = AESGCM(plaintextKey)
    plaintextData = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintextData  # Return the decrypted data

def decryptTextFile(inputFilePath):
    """
    This function handles the process of decrypting an encrypted text file.
    It reads the encrypted file, extracts the nonce, the base64-encoded encrypted key, and the ciphertext.
    Then it calls decryptData to decrypt the ciphertext and saves the decrypted data to a new file.
    """
    startTime = time.time()  # Start timing the decryption process

    outputFilePath = inputFilePath.rsplit('.enc', 1)[0]
    kmsClient = boto3.client('kms')

    with open(inputFilePath, 'rb') as file:
        nonce = file.read(12)
        encryptedKeyBase64 = file.read(248)
        encryptedKey = base64.b64decode(encryptedKeyBase64)
        ciphertext = file.read()

    print(f"Nonce length: {len(nonce)} bytes")
    print(f"Encrypted key length (base64): {len(encryptedKeyBase64)} bytes")
    print(f"Encrypted key length (decoded): {len(encryptedKey)} bytes")
    print(f"Ciphertext length: {len(ciphertext)} bytes")

    decryptedDataBytes = decryptData(ciphertext, nonce, encryptedKey, kmsClient)

    with open(outputFilePath, 'w') as file:
        file.write(decryptedDataBytes.decode())

    endTime = time.time()  # End timing the decryption process
    totalTime = endTime - startTime  # Calculate total time taken

    print(f'Decrypted text data saved to {outputFilePath} in {totalTime:.2f} seconds.')

# Get the path of the encrypted file from the user
inputEncryptedFile = getUserInputForDecryption()

# Decrypt the specified file
decryptTextFile(inputEncryptedFile)
