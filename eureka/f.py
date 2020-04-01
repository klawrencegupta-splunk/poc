#!/usr/bin/python

import boto3
import botocore
from io import BytesIO
import gzip

ACCESS_KEY='AKIAI5XJ4HGLKM5MJ6DA'
SECRET_KEY='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'

s3_resource = boto3.resource('s3')
s3 = boto3.resource('s3',
        aws_access_key_id=ACCESS_KEY,
         aws_secret_access_key= SECRET_KEY)

name = "klgdiag"
new_name = "klgdiagunpacked"
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

def s3_unpack(NEW_BUCKET):
    buffer = BytesIO(zip_obj.get()["Body"].read())
    z = gzip.GzipFile(buffer)
    for s3_file in NEW_BUCKET.objects.all():
        key_name=str(s3_file.key)
        zip_obj = s3_resource.Object(bucket_name=new_name, key=key_name)
        for filename in z.namelist():
            key_name_2=str(filename)
            file_info = z.getinfo(filename)
            s3_resource.meta.client.upload_fileobj(z.open(filename),Bucket=new_name,Key=key_name_2)

if __name__ == '__main__':
    s3_move_diag(BUCKET,NEW_BUCKET)
    s3_unpack(NEW_BUCKET)