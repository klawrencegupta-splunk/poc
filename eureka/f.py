#!/usr/bin/python

import boto3
import botocore
from io import BytesIO
import gzip
import sys

ACCESS_KEY = sys.argv[1]
SECRET_KEY = sys.argv[2]

s3_resource = boto3.resource('s3')
s3 = boto3.resource('s3',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY)

name = "klgdiag"
new_name = "klgdiagout"
BUCKET = s3.Bucket(name)
NEW_BUCKET = s3.Bucket(new_name)

def s3_move_diag(BUCKET,NEW_BUCKET):
    for s3_file in BUCKET.objects.all():
        key_name=str(s3_file.key)
        if "gz" in key_name:
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

def s3_unpack(new_name,NEW_BUCKET):
    for s3_file in NEW_BUCKET.objects.all():
        key_name=str(s3_file.key)    
    try:
        obj = s3.Object(new_name,key_name)
        #n = obj.get()['Body'].read()
        n = obj.get()['ContentDisposition'].read()
        gzipfile = BytesIO(n)
        gzipfile = gzip.GzipFile(fileobj=gzipfile)
        content = gzipfile.read()
        print(content)
    except Exception as e:
        raise
    
if __name__ == '__main__':
        s3_move_diag(BUCKET,NEW_BUCKET)
        s3_unpack(new_name,NEW_BUCKET)