#!/usr/bin/python

import boto3
import botocore

ACCESS_KEY='AKIAI5XJ4HGLKM5MJ6DA'
SECRET_KEY='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'

s3_resource = boto3.resource('s3')
s3 = boto3.resource('s3',
         aws_access_key_id=ACCESS_KEY,
         aws_secret_access_key= SECRET_KEY)

name = "klgdiag"
BUCKET = s3.Bucket(name)
NEW_BUCKET = s3.Bucket('lambdaklg1')

for s3_file in BUCKET.objects.all(): 
    key_name=str(s3_file.key)
    try:
      copy_source = {
      'Bucket': name,
      'Key': key_name}
      NEW_BUCKET.copy(copy_source, key_name)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            print("The object does not exist.")
        else:
            raise
