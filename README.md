# AWS Encryption and Data Stream Processing

This Python script demonstrates the process of decrypting and decompressing payloads retrieved from an AWS Kinesis Data Stream, specifically designed for  working with AWS Aurora Clusters.

# Description

The script utilizes various AWS services, including KMS for key management and Kinesis for data streaming. It features a custom master key provider for the AWS Encryption SDK and a cache system for efficient key management.

# Prerequisites

    AWS account with access to KMS, Aurora, and Kinesis services.
    Python 3.x installed.
    AWS SDK for Python (Boto3) and AWS Encryption SDK installed.
    Configuration for AWS credentials and region.

# Setup

    Clone the repository to your local machine.
    Install required Python packages based on the runtime version
    
    
# Usage

The script is designed to be executed as an AWS Lambda function. It can be deployed directly to Lambda or run in a local environment that simulates Lambda's execution context.
Configuration

    REGION_NAME: AWS region where your resources are located.
    RESOURCE_ID: Identifier for your Aurora Cluster.
    STREAM_NAME: Name of your Kinesis Data Stream.

# Functionality

The script performs the following steps:

    Decrypts and decompresses the payloads from Kinesis Data Stream.
    Utilizes a custom key provider for decryption.
    Manages decrypted data keys efficiently using a cache system.
    Outputs the processed data for further use or analysis.

# Security Note

This script includes a demonstration of key handling mechanisms. Ensure to follow best practices for key management and security when adapting the script for production use.
