#!/usr/bin/python
import boto3
from boto3.session import Session

ACCESS_KEY='AKIAI5XJ4HGLKM5MJ6DA'
SECRET_KEY='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'

session = Session(aws_access_key_id=ACCESS_KEY,
                  aws_secret_access_key=SECRET_KEY)
s3 = session.resource('s3')
your_bucket = s3.Bucket('klgdiag')

for s3_file in your_bucket.objects.all():
    print(s3_file.key)
