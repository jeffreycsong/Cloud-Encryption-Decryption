import boto3  # AWS Software Development Kit for Python
import os  # Module for interacting with the operating system
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # Import AES-GCM for encryption
import base64  # Module for encoding binary data into ASCII characters
import time  # Module for measuring execution time

def getUserInput():
    """
    This function prompts the user to enter various inputs required for the encryption and upload process.
    It asks for the AWS KMS Key ID, the path of the text file to encrypt, the name of the S3 bucket, and the S3 folder path.
    It returns these values for use in subsequent functions.
    """
    keyId = input("Enter AWS KMS Key ID: ")  # Prompt user to enter AWS KMS Key ID
    inputFilePath = input("Enter the path of the text file to encrypt: ")  # Prompt user to enter the file path for encryption
    bucketName = input("Enter your bucket name: ")  # Prompt user to enter the S3 bucket name
    s3Folder = input("Enter the S3 folder to store the encrypted file: ")  # Prompt user to enter the S3 folder path
    return keyId, inputFilePath, bucketName, s3Folder  # Return the collected inputs

def generateDataKey(kmsClient, keyId, keySpec='AES_256'):
    """
    This function generates a data key using AWS Key Management Service (KMS).
    It requires a KMS client, a key ID, and optionally the key specification (default is AES_256).
    It returns two versions of the key: a plaintext key for encryption and an encrypted version of the key.
    The encrypted key can be stored or transmitted securely, while the plaintext key is used for actual encryption tasks.
    """
    response = kmsClient.generate_data_key(KeyId=keyId, KeySpec=keySpec)  # Generate a data key using KMS
    return response['Plaintext'], response['CiphertextBlob']  # Return the plaintext key and its encrypted form

def encryptData(plaintextData, plaintextKey):
    """
    This function performs the encryption of data using AES-GCM (Galois/Counter Mode).
    It takes plaintext data and a plaintext key as inputs.
    It generates a nonce (number used once) required for AES-GCM, then uses this nonce along with the key to encrypt the data.
    It returns the nonce and the encrypted data. The nonce will be needed for decryption.
    """
    aesgcm = AESGCM(plaintextKey)  # Create an AESGCM object with the plaintext key
    nonce = os.urandom(12)  # Generate a 12-byte nonce for AESGCM
    ciphertext = aesgcm.encrypt(nonce, plaintextData, None)  # Encrypt the data using nonce and key
    return nonce, ciphertext  # Return the nonce and encrypted data

def uploadToS3(bucketName, fileKey, filePath):
    """
    This function uploads a file to AWS S3.
    It requires the name of the S3 bucket, the file key (path in the bucket where the file will be stored), and the local file path.
    It uses the boto3 library to create an S3 client and then uploads the file to the specified bucket and path.
    """
    s3Client = boto3.client('s3')  # Create an S3 client
    with open(filePath, 'rb') as file:  # Open the file to be uploaded
        s3Client.upload_fileobj(file, bucketName, fileKey)  # Upload the file to S3

def encryptTextFileAndUpload(inputFilePath, keyId, s3Folder, bucketName):
    """
    This is the main function that orchestrates the encryption of a text file and its upload to an AWS S3 bucket.
    It takes the path of the input text file, AWS KMS Key ID, S3 folder path, and the bucket name as inputs.
    It first generates a data key using AWS KMS, then reads and encrypts the file data using AES-GCM.
    The encrypted data, along with the nonce and the encrypted data key, is saved to a new file.
    This file is then uploaded to the specified S3 bucket and folder.
    """
    startTime = time.time()  # Record start time

    kmsClient = boto3.client('kms')
    plaintextKey, encryptedKey = generateDataKey(kmsClient, keyId)

    with open(inputFilePath, 'r') as file:
        fileData = file.read()
    fileDataBytes = fileData.encode()

    nonce, encryptedData = encryptData(fileDataBytes, plaintextKey)
    encryptedKeyBase64 = base64.b64encode(encryptedKey)

    outputFilePath = f"{inputFilePath}.enc"
    with open(outputFilePath, 'wb') as file:
        file.write(nonce)
        file.write(encryptedKeyBase64)
        file.write(encryptedData)

    s3FileKey = f"{s3Folder}/{os.path.basename(inputFilePath)}.enc"
    uploadToS3(bucketName, s3FileKey, outputFilePath)

    endTime = time.time()  # Record end time
    totalTime = endTime - startTime  # Calculate total time taken

    print(f'Encrypted file saved locally and uploaded to S3 in {totalTime:.2f} seconds.')

# Get user input
keyId, inputFilePath, bucketName, s3Folder = getUserInput()

# Encrypt and upload the file
encryptTextFileAndUpload(inputFilePath, keyId, s3Folder, bucketName)
