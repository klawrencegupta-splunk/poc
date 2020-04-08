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


#def s3_copy_diag_files(files_needed, NEW_BUCKET):
# for x in files_needed:
#with tarfile.open(x) as f:
#y=f.read()
# y=str(y)
#s3.upload_fileobj(f, new_name, y)
#print y


def s3_unpack(new_name,NEW_BUCKET):
    for s3_file in NEW_BUCKET.objects.all():
        key_name=str(s3_file.key)
        s3_object = client.get_object(Bucket=new_name,Key=key_name)
        
        # Open the tarball - code borrowed from https://github.com/Kixeye/untar-to-s3/blob/master/untar-to-s3.py #https://github.com/Kixeye
        tarball = tarfile.open(name=None, mode="r:*", fileobj=s3_object)
        files_uploaded = 0
            #Parallelize the uploads so they don't take ages
        pool = Pool(concurrency)
            
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
                
                # Wait for all transfers to finish
                    pool.join()
            
                except KeyboardInterrupt:
                # Ctrl-C pressed
                print("Cancelling upload...")
                        pool.join()

    finally:
        print("Uploaded %i files" % (files_uploaded))
    
    except tarfile.ReadError:
        print("Unable to read asset tarfile", file=sys.stderr)
        return
    except Exception as e:
        raise
    
if __name__ == '__main__':
    s3_copy_diag(BUCKET,NEW_BUCKET)
    s3_unpack(new_name,NEW_BUCKET)
