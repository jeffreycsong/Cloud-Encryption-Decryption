Text File Encryption and Decryption
This repository contains two Python scripts for encrypting and decrypting text files using AWS Key Management Service (KMS) and AES-GCM encryption:

AWSencryption.py: Encrypts a text file and uploads it to an AWS S3 bucket.
AESdecryption.py: Decrypts an encrypted file downloaded from an AWS S3 bucket.

Requirements
  Python 3.x
  Boto3 (AWS SDK for Python)
  Cryptography library
  An AWS account with access to KMS and S3 services

Setup
  Install Required Python Libraries:
    Run pip install boto3 cryptography to install the necessary Python packages.
    
  AWS Configuration:
    Ensure that AWS credentials (Access Key ID and Secret Access Key) are set up in your environment. You can configure this using AWS CLI or by setting environment variables.
    
  KMS Key and S3 Bucket:
    Create a KMS key in your AWS account for encryption and decryption.
    Create an S3 bucket where the encrypted files will be stored.
    
Usage
  Encrypting a Text File
    Run python AWSencryption.py.
    Enter the AWS KMS Key ID, path of the text file to encrypt, your S3 bucket name, and the S3 folder path when prompted.
    The script will encrypt the file and upload the encrypted version to the specified S3 bucket.
    
  Decrypting a Text File
    Download the encrypted file from your S3 bucket to your local machine.
    Run python AESdecryption.py.
    Enter the path of the encrypted file when prompted.
    The script will decrypt the file and save the plaintext content to a new file.
    
Notes
  Ensure that the AWS KMS Key ID used for encryption is the same as the one used for decryption.
  It's essential to have the necessary permissions set in AWS IAM for accessing KMS and S3 services.
