#!/usr/bin/env python
# coding=utf-8
#
# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.

# CORE PYTHON IMPORTS
import logging
import sys
import os
import time
import json
import Queue
import threading
import socket
import signal
# Splunk Python does not bundle UUID, so we've included it in the hydra bin, but it is a core python module
import uuid

# CORE SPLUNK IMPORTS
# import splunk
from cherrypy import wsgiserver
from splunk import getDefault
from splunk.appserver.mrsparkle.lib.util import splunk_to_cherry_cfg, make_splunkhome_path
import splunk.version as ver

# SA-HYDRA IMPORTS
from hydra import setupLogger


# END IMPORTS
# ------------------------------------------------------------------------------


# ===============================================================================
# Helper Class Definitions
# ===============================================================================
# Thread safe classes
class HydraCacheManager(object):
    """
    A threadsafe cache system with built in pruning for outdated caches
    """

    def __init__(self, cache_expiration=3600):
        """
        Build the cache manager initializing internal properties.
        ARGS:
            cache_expiration - time in seconds after which a cache should be removed if it has not been touched
        """
        self.cache_expiration = cache_expiration

        # This is where we keep special expirations
        # special_expirations looks like name -> special_expiration_time
        self.special_expirations = {}
        # This is where we keep stuff
        # Cache looks like name -> (touch_time, value)
        self.cache = {}
        self.cache_lock = threading.Lock()
        # Keep track of the last time we pruned
        self.last_prune = time.time()

    def prune(self):
        """
        NOT THREADSAFE! execute only inside a lock.

        Prunes the cache of all old entries, will only execute if last_prune
        plus cache_expiration is less than now in epoch
        """
        if (self.last_prune + self.cache_expiration) < time.time():
            service_logger.info("[HydraCacheManager] current cache_length=%s, checking cache for outdated entries...",
                                len(self.cache))
            to_delete = []
            now = time.time()
            # Check what we need to prune
            for name, cache_item in self.cache.iteritems():
                if (now > (cache_item[0] + self.cache_expiration)) and (now > self.special_expirations.get(name, 0)):
                    if name in self.special_expirations:
                        del self.special_expirations[name]
                    to_delete.append(name)
            # Prune the offenders
            if len(to_delete) > 0:
                service_logger.info("[HydraCacheManager] found prune_count=%s entries to remove", len(to_delete))
                for name in to_delete:
                    service_logger.debug("[HydraCacheManager] pruning cache_entry=%s", name)
                    del self.cache[name]
            else:
                service_logger.debug("[HydraCacheManager] found no entries to prune")
            # Reset last prune time
            self.last_prune = now
            service_logger.info(
                "[HydraCacheManager] finished checking cache for outdated entries, final cache_length=%s",
                len(self.cache))

    def set_cache(self, name, value, expiration=None):
        """
        Sets the cache value for a particular item, thread safe
        """
        with self.cache_lock:
            now = time.time()
            self.cache[name] = (now, value)
            if isinstance(expiration, int):
                self.special_expirations[name] = now + expiration
            self.prune()

    def get_cache(self, name):
        """
        Gets the cache value for a particular item, threadsafe
        """
        value = None
        with self.cache_lock:
            cache_item = self.cache.get(name, None)
            if cache_item is not None:
                value = cache_item[1]
                self.cache[name] = (time.time(), value)

        return value


class HydraJobExecutionInfoManager(object):
    '''
        Handle job execution time information by doing aggregation at target|task|metadata_id level
        Handles atomic job completion and error at the job name level.
    '''

    def __init__(self):
        #Dict which holds avg execution time of taregt|task|metadata_id,
        #value is tuples of avg time and total cycles reported for this key
        self.job_aggregate_execution_info = {}
        self.job_aggregate_execution_info_lock = threading.Lock()

        #Dict which holds active jobs count based upon unique target|task|metadata_id
        #We use different dictionary for this of active job count does not block other dictionary
        self.active_job_category_count = {}
        self.active_job_category_lock = threading.Lock()

        #Lists which hold the completed and error'd out atomic jobs, since
        #appends are safe we only need one lock when we clear the lists
        self.failed_atomic_jobs = []
        self.completed_atomic_jobs = []
        self.atomic_jobs_lock = threading.Lock()

    #===============================================================================
    # Atomic Job Information Methods
    #===============================================================================
    def add_completed_atomic_job(self, job_name):
        """
        Thread safe method for appending a completed atomic task's job to the
        completed atomic job list.

        @type job_name: str
        @param job_name: the name/id of the completed job

        @rtype: None
        @return: None
        """
        self.completed_atomic_jobs.append(job_name)

    def add_failed_atomic_job(self, job_name):
        """
        Thread safe method for appending a failed atomic task's job to the
        failed atomic job list.

        @type job_name: str
        @param job_name: the name/id of the failed job

        @rtype: None
        @return: None
        """
        self.failed_atomic_jobs.append(job_name)

    def get_atomic_job_info(self):
        """
        Get and clear the lists of the completed and failed atomic jobs as a
        dict.

        @rtype: dict
        @return: dict of the completed and failed atomic job lists { "completed_atomic_jobs": [...], "failed_atomic_jobs": [...] }
        """
        temp_dict = {}
        with self.atomic_jobs_lock:
            temp_dict["completed_atomic_jobs"] = self.completed_atomic_jobs
            temp_dict["failed_atomic_jobs"] = self.failed_atomic_jobs
            self.completed_atomic_jobs = []
            self.failed_atomic_jobs = []

        return temp_dict

    #===============================================================================
    # Job Execution Time Information Methods
    #===============================================================================
    def _update_active_job_dict(self, key, difference=1, put_lock=True):
        '''
           Thread safe function to update active_job_category_count dict
           @param key : Unique key based upon target|task|metadata_id
           @param difference: increment count
           @param put_lock: put lock while updating dict
           @return: nothing
        '''

        def do():
            if self.active_job_category_count.has_key(key):
                self.active_job_category_count[key] = self.active_job_category_count[key] + difference
            else:
                self.active_job_category_count[key] = difference
            # if final value is less than zero, then set it to zero
            if self.active_job_category_count[key] < 0:
                self.active_job_category_count[key] = 0

        service_logger.debug("[ReduceJobCount] Reducing job count of category=%s by=%s", key, difference)
        if put_lock:
            with self.active_job_category_lock:
                do()
        else:
            do()

    def _get_key(self, job_string):
        '''
            Extract key from job_string
            Call this function in try/except block as we are assuming that job_string will have four |
        '''
        name, target, task, metadata_id, extra = job_string.split('|', 4)
        key = target + "|" + task + "|" + metadata_id
        return key

    def abstract_activejob_category(self, things):
        '''
            Updating active job count by passing job batch count
            @param things: \n delimited strings of the form <priority_number>:<serialized JobTuple>
        '''
        for thing in things:
            if thing.find(":") != -1:
                priority_number, job_string = thing.split(":", 1)
                self.update_activejob_category(job_string, 1)

    def update_activejob_category(self, job_string, difference, put_lock=True):
        '''
            Update unclaimed job count for a specific category
            @param job_string: job string
            @param difference: count value in which unclaimed job count increases or decreases
            @param put_lock: put lock while updating dict
        '''

        try:
            service_logger.debug("[ReduceJobCount] Reducing job count of job=%s", job_string)
            key = self._get_key(job_string)
            self._update_active_job_dict(key, difference, put_lock)
            service_logger.debug("Updated active job count successfully.")
        except Exception as e:
            service_logger.exception(e)

    def update_job_execution_dict(self, job_string, exec_time, delete=False):
        '''
           Thread safe function to update job_aggregate_execution_info dict
           @param job_string : job string
           @param exec_time: Job execution time
           @param delete: Delete flags if want to delete job_aggregate_execution_info
                               Pass other parameters as None if delete flag is true
           @return: nothing
        '''
        try:
            with self.job_aggregate_execution_info_lock:
                if delete:
                    del self.job_aggregate_execution_info
                    self.job_aggregate_execution_info = {}
                else:
                    key = self._get_key(job_string)
                    if self.job_aggregate_execution_info.has_key(key):
                        # value is tuple of avg execution so far, reported execution count which is needed to calculated the count
                        # Convert this value to float so we can store large number here
                        total_reported_count = self.job_aggregate_execution_info[key][1] + 1
                        avg_value = (float)((self.job_aggregate_execution_info[key][0] *
                                             self.job_aggregate_execution_info[key][1] + float(
                            exec_time)) / total_reported_count)
                        self.job_aggregate_execution_info[key] = (avg_value, total_reported_count)
                    else:
                        self.job_aggregate_execution_info[key] = (float(exec_time), 1)
                    service_logger.debug("[JobTime] Successfully updated, key=%s, execution time=%s", key, exec_time)
        except Exception as e:
            service_logger.error(e)
            service_logger.exception(e)

    def get_aggregate_info(self):
        '''
            Return aggregation information
            @return Dict which hold category key as target|task|metadata_id, value is list of following items
              0 -- Avg execution time
              1 -- Reported times
              2 -- uncalimed job for this category
            otherwise empty dictionary
        '''
        # Aggregate both dict in one so response size would be less
        temp_dict = {}
        # get lock
        with self.job_aggregate_execution_info_lock:
            for key, values in self.job_aggregate_execution_info.iteritems():
                # value contains list of aggregate execution time, number of reported for exec time, unclaimed job count
                temp_dict[key] = [values[0], values[1], 0]
        # get another lock
        with self.active_job_category_lock:
            for key, value in self.active_job_category_count.iteritems():
                if temp_dict.has_key(key):
                    # value contains list of aggregate execution time, number of reported for exec time, unclaimed job count
                    temp_dict[key] = [temp_dict[key][0], temp_dict[key][1], value]
                else:
                    # value contains list of aggregate execution time, number of reported for exec time, unclaimed job count
                    temp_dict[key] = [0, 0, value]

        # Note update_job_execution_dict put the lock so no external lock is required
        # Delete these data as it is being reported to scheduler but self.active_job_category_count need to be present
        self.update_job_execution_dict(None, None, delete=True)

        return temp_dict


#Decorators
class HandleRequest(object):
    """
    decorator for exception handling, validating and logging requests properly
    """

    def __init__(self, expected_methods, enforce_auth=True):
        """
        Request validation utility for expected HTTP verbs
        ARGS:
            expected_methods - array of supported methods
        """
        self.expected_methods = expected_methods
        self.enforce_auth = enforce_auth

    def __call__(self, fn):
        def wrapped_fn(environ, start_response):
            start = time.time()
            #Access logging through start response calls
            def wrapped_start_response(status, response_headers):
                end = time.time()
                duration = int((end - start) * 100)
                access_logger.info("%s %s '%s' - - - %sms", environ["REQUEST_METHOD"], environ.get("SCRIPT_NAME", "/"),
                                   status, duration)
                return start_response(status, response_headers)

            global hydra_gateway_auth_token

            #Authentication
            if self.enforce_auth and environ.get("HTTP_X_HYDRA_AUTH", "") != hydra_gateway_auth_token:
                service_logger.error("authentication invalid or missing for path='%s'", environ.get("SCRIPT_NAME", "/"))
                status = "401 Unauthorized"
                response_headers = [('Content-type', 'text/plain')]
                wrapped_start_response(status, response_headers)
                return []
            #Method validation
            elif environ["REQUEST_METHOD"] not in self.expected_methods:
                service_logger.error("bad request for path='%s' got request_method='%s', expected_methods=%s",
                                     environ.get("SCRIPT_NAME", "/"), environ["REQUEST_METHOD"], self.expected_methods)
                status = "400 Bad Request"
                response_headers = [('Content-type', 'text/plain')]
                wrapped_start_response(status, response_headers)
                return []
            #Actual request handling
            else:
                try:
                    return fn(environ, wrapped_start_response)
                except Exception as e:
                    service_logger.exception("Internal Server Error on request='%s %s' specific error: %s",
                                             environ["REQUEST_METHOD"], environ.get("SCRIPT_NAME", "/"), str(e))
                    status = "500 Internal Server Error"
                    response_headers = [('Content-type', 'text/plain')]
                    wrapped_start_response(status, response_headers)
                    return []

        return wrapped_fn

#------------------------------------------------------------------------------ 

#===============================================================================
# Utilities & Globals
#===============================================================================

access_logger = setupLogger(
    logger_name="hydra-access",
    log_name="hydra_access.log",
    log_format='%(asctime)s %(levelname)s %(message)s')

service_logger = setupLogger(
    logger_name="hydra-gateway",
    log_name="hydra_gateway.log",
    log_format='%(asctime)s %(levelname)s [HydraWSGI:%(process)d] %(message)s')

# Initialize our globals

job_queue = Queue.PriorityQueue()
cache_manager = HydraCacheManager()
hydra_gateway_auth_token = None
hydra_gateway_challenge_token = None
job_exec_info_manager = HydraJobExecutionInfoManager()

# Expired job count (It is not being used, but put it for future reference)
expired_job_count = 0

# Create a lock each shared object
expired_job_count_lock = threading.Lock()

# ------------------------------------------------------------------------------

# ===============================================================================
# Hydra Cache Services
# ===============================================================================

@HandleRequest(["GET", "POST"])
def control_cache(environ, start_response):
    """
    Service for shared cache. A GET will pull the current cache value,
    a POST will set the current cache value to the POST body of the
    cache.
    Required header of X-HYDRA-CACHE-NAME will determine which cache to
    set.
    Optional header of X-HYDRA-CACHE-EXPIRY will set a special expiration on
    the cache value.
    REQUEST
        -> GET /hydra/cache
        -> POST /hydra/cache
            -> BODY of the cache value to be set
    RESPONSE
    status 200: cache set or got successfully
        -> EMPTY OR TEXT <serialized cache>
    status 400: could not find cache name to get or set
        -> EMPTY
    status 404: could not find cache of specified name
        -> EMPTY
    """

    # Validate the request

    cache_name = environ.get("HTTP_X_HYDRA_CACHE_NAME", None)
    response_headers = [("Content-type", "text/plain")]

    if cache_name is None:
        service_logger.error("bad request, no hydra cache name for path='%s'", environ.get("SCRIPT_NAME", "/"))
        status = "400 Bad Request"
        start_response(status, response_headers)
        return []

    # Parse the HTTP method

    if environ["REQUEST_METHOD"] == "GET":
        response = cache_manager.get_cache(cache_name)

        if response is None:
            status = "404 Not Found"
            start_response(status, response_headers)
            return []
        else:
            status = "200 OK"
            start_response(status, response_headers)
            return [response]
    else:
        # Implicit POST if not GET since we have method filtering
        expiration = environ.get("HTTP_X_HYDRA_CACHE_EXPIRY", None)
        if expiration is not None:
            expiration = int(expiration)
        req_in = environ.get("wsgi.input", None)
        content = req_in.read(int(environ["CONTENT_LENGTH"])).strip("\n")
        cache_manager.set_cache(cache_name, content, expiration=expiration)

        status = "200 OK"
        start_response(status, response_headers)
        return []


@HandleRequest(["POST"])
def post_cache_batch(environ, start_response):
    """
    Service for shared cache. A POST will allow the body to be processed into
    multiple cache entries. The form of the body of the request must be \n
    delimited cache entries of the form <cache_name>\t<cache_value>.
    Optional header of X-HYDRA-CACHE-EXPIRY will set a special expiration on
    the cache value.
    REQUEST
        -> POST /hydra/cache/batch
            -> BODY of the \n delmited cache entries
    RESPONSE
    status 200: batch processed successfully
        -> EMPTY
    """
    # Validate the request
    response_headers = [("Content-type", "text/plain")]
    expiration = environ.get("HTTP_X_HYDRA_CACHE_EXPIRY", None)
    if expiration is not None:
        expiration = int(expiration)
    req_in = environ.get("wsgi.input", None)
    content = req_in.read(int(environ["CONTENT_LENGTH"])).strip("\n")
    things = content.split("\n")
    service_logger.info("[CacheBatchProcessor] parsed cache batch of count=%s", len(things))
    for thing in things:
        # TODO: we could probably make this more efficient by using the found index to sub string, but whatever
        if thing.find("\t") != -1:
            cache_name, cache_value = thing.split("\t", 1)
            cache_manager.set_cache(cache_name, cache_value, expiration=expiration)

    status = "200 OK"
    start_response(status, response_headers)
    return []


# ===============================================================================
# Hydra Job Services
# ===============================================================================
@HandleRequest(["GET"])
def get_job_info(environ, start_response):
    """
    Service for determining the current job queue length.
    See the HydraJobExecutionInfoManager methods for detailed descriptions of
    the contents of "dict of key!" used below.
    REQUEST
        -> GET /hydra/job/info
    RESPONSE
        -> JSON { count: <QUEUE LENGTH>,
                expired_job_count: <EXPIRED_JOB_COUNT>,
                job_aggregate_execution_info : dict of key!
                atomic_job_info : dict of key!}
    """
    # Technically you cannot guarantee the exact queue size but this is good enough
    dict_data = {"count": job_queue.qsize()}
    # Get data from the execution info manager
    dict_data["job_aggregate_execution_info"] = job_exec_info_manager.get_aggregate_info()
    dict_data["atomic_job_info"] = job_exec_info_manager.get_atomic_job_info()
    response = json.dumps(dict_data)
    status = "200 OK"
    response_headers = [("Content-type", "application/json")]
    start_response(status, response_headers)
    return [response]


@HandleRequest(["GET"])
def get_pop_job(environ, start_response):
    """
    Service for popping out the next job to do.
    Optional arg block if 0 will 404 if it couldn't get a job, if 1 will blcok
    for 25s before 404. defaults to 1
    REQUEST
        -> GET /hydra/job/pop
        -> GET ARGS:
            block - 0 or 1 (1 by default)
    RESPONSE
    status 200: job popped successfully
        -> TEXT <serialized JobTuple>
    status 404: could not get a job (empty or blocked)
        -> EMPTY
    """
    try:
        # Parse get args
        block = True
        get_args = environ.get("QUERY_STRING", None)
        if get_args is not None and get_args != '':
            arg_list = get_args.split("&")
            for arg in arg_list:
                kv_pair = arg.split("=")
                if kv_pair[0] == "block" and len(kv_pair) == 2:
                    if kv_pair[1] == "0":
                        block = False
                    else:
                        block = True
                else:
                    service_logger.warn("[JobPopper] got unexpected get_arg=%s", kv_pair)
        # Pop a job off the queue
        priority_number, response = job_queue.get(block=block, timeout=25)

        # Update_activejob_category
        job_exec_info_manager.update_activejob_category(response, -1)

        service_logger.debug("[JobPopper] popped out job with priority_number=%s", priority_number)
        status = "200 OK"
        response_headers = [("Content-type", "text/plain")]
        start_response(status, response_headers)
        return [response]
    except Queue.Empty:
        status = "404 Not Found"
        response_headers = [("Content-type", "text/plain")]
        start_response(status, response_headers)
        return []


@HandleRequest(["POST"])
def post_job_batch(environ, start_response):
    """
    Service for adding a batch of jobs to the queue
    REQUEST
        -> POST /hydra/job/batch
        -> BODY:
            \n delimited strings of the form <priority_number>:<serialized JobTuple>
    RESPONSE
        -> EMPTY
    """
    response_headers = [("Content-type", "text/plain")]
    service_logger.debug("[JobBatchProcessor] processing batch of content_length=%s", environ["CONTENT_LENGTH"])
    req_in = environ.get("wsgi.input", None)
    # TODO: slurping could get out of hand fast, we should keep a rolling buffer going, probably with StringIO
    content = req_in.read(int(environ["CONTENT_LENGTH"]))
    things = content.split("\n")
    service_logger.debug("[JobBatchProcessor] parsed job batch of count=%s", len(things))
    for thing in things:
        # TODO: we could probably make this more efficient by using the found index to sub string, but whatever
        if thing.find(":") != -1:
            priority_number, job_string = thing.split(":", 1)
            job_queue.put((int(priority_number), job_string))

    # We are doing this after jobs is store in queue so worker will not block on this
    # Update active job count which is approx.
    job_exec_info_manager.abstract_activejob_category(things)
    status = "200 OK"
    start_response(status, response_headers)
    return []


def update_expired_job_count_var(increment_by=1):
    '''
    Thread safe function to update job_execution_info update
    @param increment_by : increment value, default is one

    @return: nothing
    '''
    with expired_job_count_lock:
        expired_job_count = expired_job_count + increment_by


@HandleRequest(["POST"])
def update_job_failure(environ, start_response):
    """
    Service for reporting a failed job. Right now only used for atomic jobs
    REQUEST
        -> POST /hydra/job/execution/failure
        -> HEADERS:
            X-HYDRA-ATOMIC-JOB: value is the job name, if not passed job is treated as not atomic (currently a bad request)
        -> BODY:
            EMPTY
    RESPONSE
        -> EMPTY
    """
    # handle atomic job failure
    atomic_job = environ.get("HTTP_X_HYDRA_ATOMIC_JOB", None)
    if atomic_job is not None:
        service_logger.info("[UpdateJobFailure] received notice of atomic job failure for job=%s", atomic_job)
        job_exec_info_manager.add_failed_atomic_job(atomic_job)
        status = "200 OK"
    else:
        status = "400 Bad Request"

    response_headers = [("Content-type", "text/plain")]
    start_response(status, response_headers)
    return []


@HandleRequest(["POST"])
def update_job_execution(environ, start_response):
    """
    Service for aggregate execution time for JobTuple
    REQUEST
        -> POST /hydra/job/execution/info
        -> HEADERS:
            X-HYDRA-ATOMIC-JOB: value is the job name, if not passed job is treated as not atomic
        -> BODY:
            strings of the form execution time in sec:<serialized JobTuple>
    RESPONSE
        -> EMPTY
    """
    service_logger.debug("[UpdateJobExecution] adding execution time")
    req_in = environ.get("wsgi.input", None)
    content = req_in.read(int(environ["CONTENT_LENGTH"]))
    # handle atomic job completion
    atomic_job = environ.get("HTTP_X_HYDRA_ATOMIC_JOB", None)
    if atomic_job is not None:
        job_exec_info_manager.add_completed_atomic_job(atomic_job)

    # handle job execution time
    if content.find(":") != -1:
        exec_time, job_string = content.split(":", 1)
        job_exec_info_manager.update_job_execution_dict(job_string, float(exec_time))
    else:
        service_logger.error("[UpdateJobExecution] Failed to process content=%s", content)
    status = "200 OK"
    response_headers = [("Content-type", "text/plain")]
    start_response(status, response_headers)
    return []


@HandleRequest(["POST"])
def update_expired_job_count(environ, start_response):
    """
    Service to update expired job count
    REQUEST
        -> POST /hydra/job/execution/expired
        -> BODY:
            strings of the valid integer number
    RESPONSE
        -> EMPTY
    """
    response_headers = [("Content-type", "text/plain")]
    service_logger.debug("[JobExpired] adding execution time")
    req_in = environ.get("wsgi.input", None)
    content = req_in.read(int(environ["CONTENT_LENGTH"]))
    try:
        update_expired_job_count_var(int(content))
        service_logger.debug("successfully updated expired job count")
    except Exception as e:
        service_logger.error("[JobExpired] failed to update expired job count content=%s, exception=%s", content, e)
        service_logger.exception(e)
    status = "200 OK"
    start_response(status, response_headers)
    return []


#===============================================================================
# Test Services
#===============================================================================
@HandleRequest(["GET"])
def test_static(environ, start_response):
    '''
    Simple static resource
    '''
    service_logger.debug("in test static environ=%s", environ)
    status = '200 OK'
    response_headers = [('Content-type', 'text/plain')]
    start_response(status, response_headers)
    return ['\n', 'Hail Hydra!', '\n']


@HandleRequest(["POST"])
def test_echo(environ, start_response):
    '''
    Simple, non-streaming echo server
    '''
    service_logger.debug("in test echo environ=%s", environ)
    status = '200 OK'
    req_in = environ.get("wsgi.input", None)
    content = req_in.read(int(environ["CONTENT_LENGTH"]))
    response_headers = [('Content-type', 'text/plain')]
    start_response(status, response_headers)
    return ["\n###########\nECHO SERVER\n###########\n", content, "\n\n"]


#===============================================================================
# Admin Services
#===============================================================================
@HandleRequest(["GET"], enforce_auth=False)
def get_challenge_key(environ, start_response):
    '''
    Return the instance challenge key. This is used to detect mismatches between
    the running gateway and splunkd's understanding of the running gateway. This
    challenge key is NOT a valid auth key
    '''
    status = '200 OK'
    response_headers = [('Content-type', 'text/plain')]
    global hydra_gateway_challenge_token
    service_logger.debug("responding to challenge request with hydra_gateway_challenge_token: %s",
                         hydra_gateway_challenge_token)
    start_response(status, response_headers)
    return [hydra_gateway_challenge_token]


# ------------------------------------------------------------------------------

# ===============================================================================
# Web Service Constructor
# ===============================================================================
def recover_cache():
    """
    Attempt to locate a serialized cache on disk and load it into the current cache.
    """
    directory = make_splunkhome_path(["etc", "apps", "SA-Hydra", "local", "run"])
    if not os.path.exists(directory):
        os.makedirs(directory)
    f = open(make_splunkhome_path(["etc", "apps", "SA-Hydra", "local", "run", "hydra_gateway.cache"]), 'r')
    serialized_cache = f.read()
    f.close()
    if serialized_cache:
        service_logger.info("attempting to deserialize cache...")
        old_cache = json.loads(serialized_cache)
        for name, cache, expiry in old_cache:
            cache_manager.set_cache(name, cache, expiration=expiry)
        service_logger.info("cache deserialized with %s entries", len(old_cache))


def serialize_cache():
    """
    Serialize the special expiration items in the cache to disk. Note we
    capture and ignore args and kwargs so this can be used as a signal handler.
    """
    service_logger.info("attempting to serialize cache...")
    directory = make_splunkhome_path(["etc", "apps", "SA-Hydra", "local", "run"])
    if not os.path.exists(directory):
        os.makedirs(directory)
    f = open(make_splunkhome_path(["etc", "apps", "SA-Hydra", "local", "run", "hydra_gateway.cache"]), 'w')
    now = time.time()
    serializable_cache = []
    for name, expiration_time in cache_manager.special_expirations.iteritems():
        serializable_cache.append((name, cache_manager.cache[name][1], (expiration_time - now)))
    service_logger.info("serializing %s cache entries", len(serializable_cache))
    f.write(json.dumps(serializable_cache))
    service_logger.info("cache serialized")
    f.close()


def bootstrap_web_service(port=8008, service_log_level="INFO", access_log_level="INFO"):
    """
    Start up the hydra web service from conf file definitions

    RETURNS reference to un-started server
    """
    # Establish the route dispatcher
    routes = {'/hydra/cache': control_cache,
              '/hydra/cache/batch': post_cache_batch,
              '/hydra/job/info': get_job_info,
              '/hydra/job/execution/info': update_job_execution,
              '/hydra/job/execution/failure': update_job_failure,
              '/hydra/job/execution/expired': update_expired_job_count,
              '/hydra/job/pop': get_pop_job,
              '/hydra/job/batch': post_job_batch,
              '/test/static': test_static,
              '/test/echo': test_echo,
              '/hydra/admin/challenge': get_challenge_key}
    dispatch = wsgiserver.WSGIPathInfoDispatcher(routes)

    # Set auth and challenge tokens
    new_key = str(uuid.uuid4())
    global hydra_gateway_auth_token
    hydra_gateway_auth_token = new_key
    new_key = str(uuid.uuid4())
    global hydra_gateway_challenge_token
    hydra_gateway_challenge_token = new_key

    # Set log levels

    access_log_level = access_log_level.upper()

    if access_log_level not in ["DEBUG", "INFO", "WARN", "WARNING", "ERROR"]:
        access_logger.setLevel(logging.INFO)
        access_logger.warning(
            "unrecognizable configured access log level: %s, resetting log level to INFO", access_log_level)
    else:
        access_logger.setLevel(access_log_level)

    service_log_level = service_log_level.upper()

    if service_log_level not in ["DEBUG", "INFO", "WARN", "WARNING", "ERROR"]:
        service_logger.setLevel(logging.INFO)
        service_logger.warning(
            "unrecognizable configured service logging level: %s, resetting logging level to INFO", service_log_level)
    else:
        service_logger.setLevel(service_log_level)

    # Get basic configuration
    global_cfg = splunk_to_cherry_cfg('web', 'settings')
    host_name = getDefault("host")

    # Get SSL configuration
    service_logger.info('parsing SSL config from splunk web.conf...')

    """Added this condition to support the Splunk Ivory release - Jira ticket VMW-4377 and NETAPP-638 """
    if ver.__version__ > '6.4.9':
        private_key_path = str(global_cfg['privKeyPath']).replace('$SPLUNK_HOME/', '')
        ssl_certificate = str(global_cfg['serverCert']).replace('$SPLUNK_HOME/', '')
    else:
        private_key_path = str(global_cfg['privKeyPath'])
        ssl_certificate = str(global_cfg['caCertPath'])
    if os.path.isabs(private_key_path):
        global_cfg['server.ssl_private_key'] = private_key_path
    else:
        global_cfg['server.ssl_private_key'] = make_splunkhome_path([private_key_path])
    if os.path.isabs(ssl_certificate):
        global_cfg['server.ssl_certificate'] = ssl_certificate
    else:
        global_cfg['server.ssl_certificate'] = make_splunkhome_path([ssl_certificate])

    # Validate Configuration
    if not os.path.exists(global_cfg['server.ssl_private_key']):
        service_logger.error("Failed to bootstrap hydra service due to configured ssl key missing: %s",
                             global_cfg['server.ssl_private_key'])
        raise ValueError("Private Key: '%s' Not Found" % global_cfg['server.ssl_private_key'])
    if not os.path.exists(global_cfg['server.ssl_certificate']):
        service_logger.error("Failed to bootstrap hydra service due to configured ssl cert missing: %s",
                             global_cfg['server.ssl_certificate'])
        raise ValueError("Certificate: '%s' Not Found" % global_cfg['server.ssl_certificate'])



    global_cfg['server.ssl_options'] = 0

    if 'cipherSuite' in global_cfg and global_cfg.get('cipherSuite'):
        global_cfg['server.ssl_ciphers'] = str(global_cfg['cipherSuite'])

    if 'sslVersions' in global_cfg:
        try:
            from ssl import PROTOCOL_SSLv3, PROTOCOL_SSLv23, PROTOCOL_TLSv1, PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2, OP_NO_SSLv2, OP_NO_SSLv3

            acceptedSSLVersions = {
                'all':       {'server.ssl_version': PROTOCOL_SSLv23},
                'ssl3':      {'server.ssl_version': PROTOCOL_SSLv3},
                'tls1.0':    {'server.ssl_version': PROTOCOL_TLSv1},
                'tls1.1':    {'server.ssl_version': PROTOCOL_TLSv1_1},
                'tls1.2':    {'server.ssl_version': PROTOCOL_TLSv1_2},
                'ssl3, tls': {'server.ssl_version': PROTOCOL_SSLv23,
                              'server.ssl_options': OP_NO_SSLv2},
                'tls':       {'server.ssl_version': PROTOCOL_SSLv23,
                              'server.ssl_options': OP_NO_SSLv2 | OP_NO_SSLv3}
            }

        except ImportError:
            from ssl import PROTOCOL_SSLv3, PROTOCOL_SSLv23, PROTOCOL_TLSv1
            acceptedSSLVersions = {
                'all':       {'server.ssl_version': PROTOCOL_SSLv23},
                'ssl3':      {'server.ssl_version': PROTOCOL_SSLv3},
                'tls1.0':    {'server.ssl_version': PROTOCOL_TLSv1}
        }
        
        if global_cfg['sslVersions'] in acceptedSSLVersions:
            global_cfg.update(acceptedSSLVersions[global_cfg['sslVersions']])



        else:
            #default case ssl2+
            service_logger.warn("Undefined sslVersion='%s'. Please select from 'all', 'ssl3, tls' or 'tls'." % global_cfg.get('sslVersions'))
            service_logger.warn("Defaulting sslVersion to 'all'")
            global_cfg['server.ssl_version'] = PROTOCOL_SSLv23

    else:
        # No 'sslVersions'-- old and possibly POODLE-problematic.
        try:
            from _ssl import PROTOCOL_SSLv23_NO23
            global_cfg['server.ssl_version'] = PROTOCOL_SSLv23_NO23
        except ImportError:
            service_logger.warning("POODLE Vulnerable: Please update to Splunk v6.0.7, v6.1.5, or v6.2.1 or higher for protection.")

    # Validate port availability--since we can't start the server--and then write the key files we need to validate
    # prior to start
    try:
        sock = socket.socket()
        sock.connect((host_name, port))
        sock.close()
        service_logger.error("[%s:%d] could not bootstrap gateway because port=%d is in use", host_name, port, port)
        sys.exit(1)
    except socket.error as e:
        if e.errno == 10061:
            service_logger.debug('[%s:%d] port=%d is available.', host_name, port, port)
        else:
            service_logger.warning('[%s:%d] unexpected socket error: %s', host_name, port, e)
        pass

    # Build server
    server = wsgiserver.CherryPyWSGIServer(('0.0.0.0', port), dispatch, server_name=host_name)
    for key in ('ssl_private_key', 'ssl_options', 'ssl_version', 'ssl_certificate', 'ssl_ciphers'):
        if 'server.'+key in global_cfg:
            setattr(server, key, global_cfg['server.'+key])

    # Commit tokens to filesystem
    directory = make_splunkhome_path(["etc", "apps", "SA-Hydra", "local", "run"])
    if not os.path.exists(directory):
        os.makedirs(directory)
    f = open(make_splunkhome_path(["etc", "apps", "SA-Hydra", "local", "run", "hydra_gateway.key"]), 'w')
    f.write("\n".join([hydra_gateway_challenge_token, hydra_gateway_auth_token, "\n"]))

    # Attempt to recover existing cache, if any
    try:
        recover_cache()
    except Exception as e:
        service_logger.warning("unable to recover a serialized cache, message=%s", str(e))

    # Bind a cache serialization to SIGTERM and SIGINT
    def signal_handler(sig, frame):
        """
        Handle signals and terminate the process while preserving state.
        """
        service_logger.info("initiating safe shutdown after receiving signal=%s", sig)
        service_logger.info("stopping cherrypy wsgi server")
        server.stop()
        service_logger.info("cherrypy wsgi server stopped")
        serialize_cache()
        service_logger.info("exiting parent process")
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    return server


if __name__ == "__main__":
    try:
        server = bootstrap_web_service()
        server.start()
    except ValueError as e:
        service_logger.exception("Failed to bootstrap hydra service due to configuration error: %s", str(e))
