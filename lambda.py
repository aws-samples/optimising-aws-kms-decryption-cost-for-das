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


REGION_NAME = ""  # Region
RESOURCE_ID = ""  # Aurora Cluster ID
STREAM_NAME = ""  # Kinesis Data Stream name

enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)


class MyRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "BC"

    def __new__(cls, *args, **kwargs):
        obj = super(RawMasterKeyProvider, cls).__new__(cls)
        return obj

    def __init__(self, plain_key):
        RawMasterKeyProvider.__init__(self)
        self.wrapping_key = WrappingKey(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
                                        wrapping_key=plain_key, wrapping_key_type=EncryptionKeyType.SYMMETRIC)

    def _get_raw_key(self, key_id):
        return self.wrapping_key


### THIS IS SIMPLY A DEMO ON HOW TO RETAIN DECRYPTED DATA KEYS
### ALWAYS STORE KEYS IN SECURE STRUCTURES
class KMSDataKeyCache():
    def __init__(self, session):
        self.kms_client = session.client('kms', region_name=REGION_NAME)
        # For this demo we will just use a dict, but an expiring cache is ideal
        self.key_cache = {}

    def getDecrypted(self, data_key_decoded):
        if data_key_decoded in self.key_cache:
            # If we've already decrypted this key, then no need to call KMS
            return self.key_cache[data_key_decoded]
        else:
            # If we don't have a decrypted copy of this key, then get one from KMS
            data_key_decrypt_result = self.kms_client.decrypt(CiphertextBlob=data_key_decoded,
                                                              EncryptionContext={'aws:rds:dbc-id': RESOURCE_ID})
            self.key_cache[data_key_decoded] = data_key_decrypt_result['Plaintext']
            return self.key_cache[data_key_decoded]


def decrypt_payload(payload, data_key):
    my_key_provider = MyRawMasterKeyProvider(data_key)
    my_key_provider.add_master_key("DataKey")
    decrypted_plaintext, header = enc_client.decrypt(
        source=payload,
        materials_manager=aws_encryption_sdk.materials_managers.default.DefaultCryptoMaterialsManager(
            master_key_provider=my_key_provider))
    return decrypted_plaintext


def decrypt_decompress(payload, key):
    decrypted = decrypt_payload(payload, key)
    return zlib.decompress(decrypted, zlib.MAX_WBITS + 16)


def lambda_handler(event, context):
    session = boto3.session.Session()
    # Initialize a cache to get KMS data keys from
    kms_data_key_cache = KMSDataKeyCache(session)
    # Initialize Kinesis client
    kinesis = session.client('kinesis', region_name=REGION_NAME)
    # Iterate over all shards in the DAS stream and get records
    response = kinesis.describe_stream(StreamName=STREAM_NAME)
    shard_iters = []
    for shard in response['StreamDescription']['Shards']:
        shard_iter_response = kinesis.get_shard_iterator(StreamName=STREAM_NAME, ShardId=shard['ShardId'],
                                                         ShardIteratorType='LATEST')
        shard_iters.append(shard_iter_response['ShardIterator'])

    while len(shard_iters) > 0:
        next_shard_iters = []
        for shard_iter in shard_iters:
            response = kinesis.get_records(ShardIterator=shard_iter, Limit=10000)
            for record in response['Records']:
                record_data = record['Data']
                # Deserialize DAS payload to python object
                record_data = json.loads(record_data)
                # Base64 decode the payload
                payload_decoded = base64.b64decode(record_data['databaseActivityEvents'])
                data_key_decoded = base64.b64decode(record_data['key'])
                # Request a decrypted copy of the key from the cache
                # (which will only call KMS the first time we see a particular data key)
                data_key_decrypted = kms_data_key_cache.getDecrypted(data_key_decoded)
                decrypted = decrypt_payload(payload_decoded, data_key_decrypted)
                decrypted_das_records = zlib.decompress(decrypted, zlib.MAX_WBITS + 16)
                print(decrypted_das_records)
            if 'NextShardIterator' in response:
                next_shard_iters.append(response['NextShardIterator'])
        shard_iters = next_shard_iters

    return {
        'statusCode': 200,
        'body': 'Processing Complete'
    }
