#!/usr/bin/python

import boto3
import botocore

ACCESS_KEY='AKIAI5XJ4HGLKM5MJ6DA'
SECRET_KEY='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'

s3_client = boto3.client('s3')
s3 = boto3.resource('s3',
         aws_access_key_id=ACCESS_KEY,
         aws_secret_access_key= SECRET_KEY)

BUCKET_NAME = s3.Bucket('klgdiag')

for s3_file in BUCKET_NAME.objects.all():
    try:
        BUCKET_NAME.download_file(s3_file.key, '/tmp/a.tar')
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            print("The object does not exist.")
        else:
            raise





