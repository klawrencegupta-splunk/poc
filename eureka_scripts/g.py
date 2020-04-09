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
    s3_object = s3client.get_object(Bucket=new_name, Key=keys)
    wholefile = s3_object['Body'].read()
    fileobj = io.BytesIO(wholefile)
    tarf = tarfile.open(fileobj=fileobj)


s3_object = client.get_object(Bucket=new_name, Key=keys)
    for x in s3_object:
        tarf = tarfile.open(x)
        compressed = tarf.extractall()
        data = pd.read_csv(compressed,sep="\t")
        NEW_BUCKET.put_file_objects(data)
    return data

if __name__ == '__main__':
    s3_copy_diag(BUCKET,NEW_BUCKET)
    s3_keys = get_s3_objects(NEW_BUCKET)
#get_from_archive(new_name,s3_keys,NEW_BUCKET)


