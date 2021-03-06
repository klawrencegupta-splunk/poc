#!/usr/bin/python

import boto3
import io
import botocore
import tarfile
import sys
import mimetypes
import logging
import argparse

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
#listOflogs =["splunkd.log","resource_usage.log","audit.log","metrics.log"]
#for x in s3_all_files:
#data = get_from_archive(x)
#put_file_objects(x,NEW_BUCKET)

#make a copy of the original diag in case of fuckity
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

def get_s3_objects(NEW_BUCKET):
    for s3_file in NEW_BUCKET.objects.all():
        key_name=str(s3_file.key)
        print key_name
        return key_name

def get_from_archive(new_name,keys,NEW_BUCKET):
    s3_object = client.get_object(Bucket=new_name, Key=keys)
    wholefile = s3_object['Body'].read()
    fileobj = io.BytesIO(wholefile)
    filename = tarfile.open(fileobj=fileobj)
    data = filename.extractall()
    # Parse as TSV and return the results
    return data


#NEW_BUCKET.put_object(data,"klg1")
#NEW_BUCKET.upload_fileobj(data, 'klg1')

if __name__ == '__main__':
    s3_copy_diag(BUCKET,NEW_BUCKET)
    keys = get_s3_objects(NEW_BUCKET)
    print keys
    data = get_from_archive(new_name,keys,NEW_BUCKET)
    NEW_BUCKET.upload_fileobj(data,"diag")


