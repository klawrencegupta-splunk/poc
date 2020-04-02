#!/usr/bin/python

import boto3
import botocore
import io
import gzip
import tarfile
import sys

ACCESS_KEY = sys.argv[1]
SECRET_KEY = sys.argv[2]

s3_resource = boto3.resource('s3')
client = boto3.client('s3')
s3 = boto3.resource('s3',
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY)

name = "klgdiag"
new_name = "klgdiagout"
BUCKET = s3.Bucket(name)
NEW_BUCKET = s3.Bucket(new_name)


# List of string 
listOflogs =["splunkd.log","resource_usage.log","audit.log","metrics.log"]

def s3_copy_diag(BUCKET,NEW_BUCKET):
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


def s3_copy_diag_files(files_needed, NEW_BUCKET):
            try:
                copy_source = {
                'Bucket': new_name,
               'Key': files_needed}
                NEW_BUCKET.copy(copy_source, key_name)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == "404":
                    print("The object does not exist.")
                else:
                    raise


def s3_unpack(new_name,NEW_BUCKET):
    for s3_file in NEW_BUCKET.objects.all():
        key_name=str(s3_file.key)
        s3_object = client.get_object(Bucket=new_name,Key=key_name)
        
    try:
        wholefile = s3_object['Body'].read()
        fileobj = io.BytesIO(wholefile)
        tarf = tarfile.open(fileobj=fileobj)
        names = tarf.getnames() 
        for name in names:
            name=str(name)
            for x in listOflogs:
                if x in name:
                   print(name)
                   return x
    except Exception as e:
        raise
    
if __name__ == '__main__':
        s3_copy_diag(BUCKET,NEW_BUCKET)
        files_needed = s3_unpack(new_name,NEW_BUCKET)
        s3_copy_diag_files(files_needed, NEW_BUCKET)