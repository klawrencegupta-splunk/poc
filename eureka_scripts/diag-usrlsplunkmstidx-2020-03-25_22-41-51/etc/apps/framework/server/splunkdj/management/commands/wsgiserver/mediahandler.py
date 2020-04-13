#!/usr/bin/env python
# -*- coding: utf-8 -*-
# fix these up
import os, stat, mimetypes
import django
from django.utils.http import http_date
from django.conf import settings
from django.contrib.staticfiles import finders

import logging
logger = logging.getLogger('splunk')

class BlockIterator(object):
    # Vlada Macek Says:
    # September 29th, 2009 at 14:42
    # You’re handing the static files by

    #                output = [fp.read()]
    #                fp.close()

    # which causes entire content is loaded to the memory (and not only once
    # by my observation). This is unacceptable for large files. I found this
    # to be much more memory & CPU efficient:

    def __init__(self, fp):
        self.fp = fp
        
    def __iter__(self):
           return self

    def next(self):
        chunk = self.fp.read(20*1024)
        if chunk:
            return chunk
        self.fp.close()
        raise StopIteration

class MediaHandler( object ):

    def __init__( self, media_root ):
        self.media_root = media_root

    def __call__( self, environ, start_response ):

        def done( status, headers, output ):
            start_response( status, headers.items() )
            return output

        path_info = environ['PATH_INFO']
        # Normalize a pathname by collapsing redundant separators and up-level references so that A//B, A/B/, A/./B and A/foo/../B all become A/B. Example /../../../../../../../../../etc/passwd will be converted to /etc/passwd using os.path.normpath method.
        path_info = os.path.normpath(path_info).lstrip(os.sep)
        file_path = os.path.join( self.media_root, path_info )        

        if not os.path.exists( file_path ):
            file_path = finders.find(path_info)
            if not file_path or not os.path.exists( file_path ):
                status = '404 NOT FOUND'
                headers = {'Content-type': 'text/plain'}
                output = ['Page not found: %s' % path_info]
                return done( status, headers, output )

        try:
            fp = open( file_path, 'rb' )
        except IOError, e:
            status = '401 UNAUTHORIZED'
            headers = {'Content-type': 'text/plain'}
            output = ['Permission denied: %s' % file_path]
            return done( status, headers, output )

        # This is a very simple implementation of conditional GET with
        # the Last-Modified header. It makes media files a bit speedier
        # because the files are only read off disk for the first request
        # (assuming the browser/client supports conditional GET).

        mtime = str(http_date( os.stat(file_path)[stat.ST_MTIME] ))
        headers = {'Last-Modified': mtime}
        if environ.get('HTTP_IF_MODIFIED_SINCE', None) == mtime:
            status = '304 NOT MODIFIED'
            output = []
        else:
            status = '200 OK'
            mime_type = mimetypes.guess_type(file_path)[0]
            if mime_type:
                headers['Content-Type'] = mime_type

            #output = [fp.read()]
            # fp.close()
            output = BlockIterator(fp)
            
        return done( status, headers, output )


