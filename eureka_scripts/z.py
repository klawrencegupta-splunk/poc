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
                   'Delimiter' = '.tar.gz'}
                NEW_BUCKET.copy(copy_source, key_name)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == "404":
                    print("The object does not exist.")
                else:
                    raise


#def s3_copy_diag_files(files_needed, NEW_BUCKET):
# for x in files_needed:
#with tarfile.open(x) as f:
#y=f.read()
# y=str(y)
#s3.upload_fileobj(f, new_name, y)
#print y

# Open the tarball - code borrowed from https://github.com/Kixeye/untar-to-s3/blob/master/untar-to-s3.py #https://github.com/Kixeye

# Reads a lookup file from an archive (fileobj)
def get_from_archive(fileobj, compressed_file):
    # Open the archive
    tarf = tarfile.open(fileobj=fileobj)
    
    # Get the file of interest
    compressed = tarf.extractfile(compressed_file)
    
    # Parse as TSV and return the results
    data = pd.read_csv(compressed,sep="\t")
    return data

get_from_archive(fileobj, "events.tsv")

def s3_unpack(new_name,NEW_BUCKET):
    for s3_file in NEW_BUCKET.objects.all():
        key_name=str(s3_file.key)
        s3_object = client.get_object(Bucket=new_name,Key=key_name)
        tarball = tarfile.open(name=key_name, mode="r:*", fileobj=s3_object.fileobj)
        files_uploaded = 0
        pool = Pool(concurrency)
        #Parallelize the uploads so they don't take ages
        # Iterate over the tarball's contents.
        try:
            for member in tarball:
                    # Ignore directories, links, devices, fifos, etc.
                if not member.isfile():
                    continue
                    # Mimic the behaviour of tar -x --strip-components=
                    stripped_name = member.name.split('/')[strip_components:]
                    if not bool(stripped_name):
                        continue
                        path = os.path.join(prefix, '/'.join(stripped_name))
                    # Read file data from the tarball
                        fd = tarball.extractfile(member)
                    # Send a job to the pool.
                        pool.wait_available()
                        pool.apply_async(__deploy_asset_to_s3, (fd.read(), path, member.size, bucket, not no_compress))
                        files_uploaded += 1
                        pool.join()
        except KeyboardInterrupt:
                # Ctrl-C pressed
            print("Cancelling upload...")
            pool.join()

if __name__ == '__main__':
    s3_copy_diag(BUCKET,NEW_BUCKET)
    s3_unpack(new_name,NEW_BUCKET)
