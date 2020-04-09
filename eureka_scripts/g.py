#!/usr/bin/python

import boto3
import io
#import gzip
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

#make a copy of the original diag in case of fuckity
def s3_copy_diag(BUCKET,NEW_BUCKET):
    for s3_file in BUCKET.objects.all():
        key_name=str(s3_file.key)
        if "gz" in key_name:
            try:
                copy_source = {
                'Bucket': name,
               'Key': key_name,
                   'Delimiter': '.tar.gz'}
                NEW_BUCKET.copy(copy_source, key_name)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == "404":
                    print("The object does not exist.")
                else:
                    raise
def get_s3_objects(NEW_BUCKET):
    for s3_file in NEW_BUCKET.objects.all():
        names = tarf.getnames()
        if "splunkd" in names:
            return names


def get_from_archive(fileobj, compressed_file):
    # Open the archive
    tarf = tarfile.open(fileobj=fileobj)
    # Get the file of interest
    compressed = tarf.extractfile(compressed_file)
    # Parse as TSV and return the results
    data = pd.read_csv(compressed,sep="\t")
    return data

def put_file_objects(data, NEW_BUCKET):
    NEW_BUCKET.put_file_objects(data)


if __name__ == '__main__':
    s3_copy_diag(BUCKET,NEW_BUCKET)
    files = get_s3_objects(NEW_BUCKET)
    data = get_from_archive(files)
    put_file_objects(data,NEW_BUCKET)
