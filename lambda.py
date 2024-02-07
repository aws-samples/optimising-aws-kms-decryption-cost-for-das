/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: MIT-0
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import json
import zlib
import aws_encryption_sdk
import boto3
import base64
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType

# Constants for AWS resources and region. Please use environment variables instead

REGION_NAME = ""  # Region
RESOURCE_ID = ""  # Aurora Cluster ID
STREAM_NAME = ""  # Kinesis Data Stream name

# Initialize the AWS Encryption SDK client with a specific commitment policy
enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

# Custom key provider class for raw encryption/decryption operations
class MyRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "BC"  # Custom provider ID

    def __new__(cls, *args, **kwargs):
        # Overriding the object creation process for proper initialization
        obj = super(RawMasterKeyProvider, cls).__new__(cls)
        return obj

    def __init__(self, plain_key):
        # Initializing the parent class and setting up a wrapping key
        super().__init__()
        self.wrapping_key = WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=plain_key,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC)

    def _get_raw_key(self, key_id):
        # Method to retrieve the raw key; here, it returns the initialized wrapping key
        return self.wrapping_key

# Class for caching decrypted data keys using AWS KMS
class KMSDataKeyCache():
    def __init__(self, session):
        # Initialize the KMS client and a simple dictionary for caching keys
        self.kms_client = session.client('kms', region_name=REGION_NAME)
        self.key_cache = {}

    def getDecrypted(self, data_key_decoded):
        # Attempt to retrieve the decrypted key from cache or decrypt it using KMS
        if data_key_decoded in self.key_cache:
            return self.key_cache[data_key_decoded]
        else:
            # Decrypt the key using KMS and store it in the cache
            data_key_decrypt_result = self.kms_client.decrypt(
                CiphertextBlob=data_key_decoded,
                EncryptionContext={'aws:rds:dbc-id': RESOURCE_ID})
            self.key_cache[data_key_decoded] = data_key_decrypt_result['Plaintext']
            return data_key_decrypt_result['Plaintext']

# Function to decrypt payload with a provided data key
def decrypt_payload(payload, data_key):
    # Setup the key provider and decrypt the payload
    my_key_provider = MyRawMasterKeyProvider(data_key)
    my_key_provider.add_master_key("DataKey")
    decrypted_plaintext, header = enc_client.decrypt(
        source=payload,
        materials_manager=aws_encryption_sdk.materials_managers.default.DefaultCryptoMaterialsManager(
            master_key_provider=my_key_provider))
    return decrypted_plaintext

# Function to decrypt and then decompress the payload
def decrypt_decompress(payload, key):
    decrypted = decrypt_payload(payload, key)
    return zlib.decompress(decrypted, zlib.MAX_WBITS + 16)

# The main Lambda handler function
def lambda_handler(event, context):
    # Initialize a session and the KMS data key cache
    session = boto3.session.Session()
    kms_data_key_cache = KMSDataKeyCache(session)

    # Process each record in the event
    for record in event['Records']:
        try:
            # Decode and parse the incoming data
            data = base64.b64decode(record['kinesis']['data'])
            record_data = json.loads(data)
            payload_decoded = base64.b64decode(record_data['databaseActivityEvents'])
            data_key_decoded = base64.b64decode(record_data['key'])

            # Get the decrypted data key from the cache or KMS
            decrypted_data_key = kms_data_key_cache.getDecrypted(data_key_decoded)

            # Decrypt and decompress the payload
            decrypted_decompressed_payload = decrypt_decompress(payload_decoded, decrypted_data_key)
            plaintext = decrypted_decompressed_payload.decode('utf-8')

            # Load the JSON events and log them
            events = json.loads(plaintext)
            print("Processed events:", events)

        except Exception as e:
            # Log any errors encountered during processing
            print(f"Error processing record: {str(e)}")

    # Return a success status code and message
    return {
        'statusCode': 200,
        'body': json.dumps('Processing Complete')
}
