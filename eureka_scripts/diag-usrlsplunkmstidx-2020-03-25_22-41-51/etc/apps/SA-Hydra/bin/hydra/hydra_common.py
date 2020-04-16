# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
#CORE PYTHON IMPORTS
import os
import datetime
import cPickle
import urllib2
import json
from base64 import b64encode, b64decode
from collections import namedtuple
from time import mktime, sleep

#SPLUNK IMPORTS
import splunk.entity as en
#from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

#Basic Job Named Tuple
JobTuple = namedtuple("JobTuple", "name target task metadata_id create_time last_time expiration_period special")


class HydraCommon(object):
    """
    This class contains utility methods or variables used across the scheduler and
    worker classes.
    """

    @staticmethod
    def getConfModTime(app_home, conf, collection_conf_name=None):
        """
        Get the modification time for the specified conf, collect or node

        return epoch time for conf modification
        """
        if app_home == None:
            raise NotImplementedError("app_home must not be None")
        conf_name = None
        if conf == "collection":
            if collection_conf_name == None:
                raise NotImplementedError("Collection Conf Name Must Be Specified")
            conf_name = collection_conf_name
        elif conf == "node":
            conf_name = "hydra_node.conf"
        elif conf == "metadata":
            conf_name = "hydra_metadata.conf"
        else:
            raise NotImplementedError("Unrecognized Conf Parameter in getConfModTime")

        default_path = os.path.join(app_home, "default", conf_name)
        local_path = os.path.join(app_home, "local", conf_name)
        if os.path.exists(default_path):
            default_time = os.path.getmtime(default_path)
        else:
            default_time = 0
        if os.path.exists(local_path):
            local_time = os.path.getmtime(local_path)
        else:
            local_time = 0
        return max(default_time, local_time)


class HydraGatewayAdapter(object):
    """
    This class acts as the go between for schedulers and workers and the
    hydra gateway service.
    """

    def __init__(self, splunkd_uri, splunk_session_key, gateway_uri):
        self.splunkd_uri = splunkd_uri
        self.splunk_session_key = splunk_session_key
        self.gateway_uri = gateway_uri.rstrip("/")
        self.authenticate_gateway()

    def authenticate_gateway(self):
        """
        Call out to splunkd to get the key to the hydra gateway
        """
        for retry in range(4):
            entity = en.getEntity("/hydra/hydra_gatekeeper", "hydra_gateway", sessionKey=self.splunk_session_key,
                                  hostPath=self.splunkd_uri)
            self.gateway_auth_key = entity["key"]
            if self.gateway_auth_key != "DEFER":
                self.opener = urllib2.build_opener()
                self.opener.addheaders = [('X-hydra-auth', self.gateway_auth_key)]
                break
            else:
                #Give the gateway time to come up
                sleep(2)
        else:
            raise Exception("[HydraGatewayAdapter] could not authenticate with gateway after %s retries" % (str(retry)))

    #Cache Endpoint Wrappers:
    def get_cache(self, name):
        """
        Get the current cache value for the given name.
        Note that caches are assumed to be JSON serializable and deserializable
        ARGS:
            name - the name of the cache entry

        RETURNS deserialized cache value or None if it does not exist
        """
        uri = self.gateway_uri + "/hydra/cache"
        headers = {"X-HYDRA-CACHE-NAME": name}
        req = urllib2.Request(uri, headers=headers)
        try:
            resp = self.opener.open(req)
            return json.loads(resp.read())
        except urllib2.HTTPError as e:
            if e.code == 404:
                return None
            else:
                raise e

    def set_cache(self, name, value, expiration=None):
        """
        Set the current cache value for the given name.
        Note that caches are assumed to be JSON serializable and deserializable

        @type name: str
        @param name: the name of the cache entry
        @type value: json serializable object
        @param value: JSON serializable python object (dict preferred)
        @type expiration: int or None
        @param expiration: the period in sec from set time after which the cache should be cleared

        @rtype: int
        @return: the response code of the cache request
        """
        uri = self.gateway_uri + "/hydra/cache"
        headers = {"X-HYDRA-CACHE-NAME": name}
        if isinstance(expiration, int):
            headers["X-HYDRA-CACHE-EXPIRY"] = str(expiration)
        body = json.dumps(value)
        req = urllib2.Request(uri, headers=headers, data=body)
        try:
            resp = self.opener.open(req)
            return resp.code
        except urllib2.HTTPError as e:
            return e.code

    def set_cache_batch(self, cache_items, expiration=None):
        """
        Set a batch of caches to the gateway cache.
        Note that caches are assumed to be JSON serializable and deserializable

        @type cache_items: iterable of tuples of the form (<cache_name>, <cache_value>)
        @param cache_items: the set of cache name and value pairs to be set in the gateway cache
        @type expiration: int or None
        @param expiration: the period from set time after which the cache should be cleared

        @rtype: int
        @return: the response code of the cache request
        """
        uri = self.gateway_uri + "/hydra/cache/batch"
        headers = {}
        if isinstance(expiration, int):
            headers["X-HYDRA-CACHE-EXPIRY"] = str(expiration)
        body_list = []
        for name, value in cache_items:
            body_list.append(name + "\t" + json.dumps(value))
        body = "\n".join(body_list)
        req = urllib2.Request(uri, headers=headers, data=body)
        try:
            resp = self.opener.open(req)
            return resp.code
        except urllib2.HTTPError as e:
            return e.code

    #Job Endpoint Wrappers:
    def get_job_count(self):
        """
        Get the current job count.

        RETURNS job count (int)
        """
        req = urllib2.Request(self.gateway_uri + "/hydra/job/info")
        resp = self.opener.open(req)
        resp_dict = json.loads(resp.read())
        return resp_dict['count']

    def get_job_info(self):
        """
        Get the current job information.

        RETURNS job information dict which hold the following values
            count: total unclaimed job count
            expiry_job_count: expired job so far on this gateway
            job_aggregate_execution_info: is a dict
                key: target|task|metadata_id
                value: is array of three items
                    0: aggregate execution time
                    1: number of times execution time is reported for this category
                    2: unclaimed job count for this category
            atomic_job_info is a dict
                key: completed_atomic_jobs
                value: list of completed job names/ids
                key: failed_atomic_jobs
                value: list of failed job names/ids
        """
        req = urllib2.Request(self.gateway_uri + "/hydra/job/info")
        resp = self.opener.open(req)
        resp_dict = json.loads(resp.read())
        return resp_dict

    def report_failed_atomic_job(self, job_tuple):
        '''
        Calling gateway to commit failed atomic job execution.

        @type job_tuple: JobTuple
        @param job_tuple: the JobTuple object for the failed job

        @rtype: int
        @return: return code from gateway
        '''
        uri = self.gateway_uri + "/hydra/job/execution/failure"

        #Handle Atomic Job
        headers = {}
        headers["X-HYDRA-ATOMIC-JOB"] = job_tuple.name

        req = urllib2.Request(uri, headers=headers, data="")
        try:
            resp = self.opener.open(req, timeout=60)
            return resp.code
        except urllib2.HTTPError as e:
            return e.code

    def commit_job_exec_info(self, time_spent, job_tuple, is_atomic=False):
        '''
        Calling gateway to commit job execution information

        @type time_spent: int
        @param time_spent: total time is taken by job
        @type job_tuple: JobTuple
        @param job_tuple: the JobTuple object for the completed job
        @type is_atomic: bool
        @param is_atomic: True if the job's task was atomic, False otherwise

        @rtype: int
        @return: return code from gateway
        '''
        uri = self.gateway_uri + "/hydra/job/execution/info"

        #Handle Job Execution Info
        serialized_job = self.serialize_job(job_tuple);
        content = str(time_spent) + ":" + serialized_job

        #Handle Atomic Job
        headers = {}
        if is_atomic:
            headers["X-HYDRA-ATOMIC-JOB"] = job_tuple.name

        req = urllib2.Request(uri, headers=headers, data=content)
        try:
            resp = self.opener.open(req, timeout=60)
            return resp.code
        except urllib2.HTTPError as e:
            return e.code

    def get_next_job(self, block=True):
        """
        Get and deserialize the next job in priority order.
        If no jobs available, i.e. 404, return None
        ARGS:
            block - if false do not wait for job if not available for any reason, return immediately

        RETURNS JobTuple
        """
        if block:
            uri = self.gateway_uri + "/hydra/job/pop"
        else:
            uri = self.gateway_uri + "/hydra/job/pop?block=0"
        req = urllib2.Request(uri)
        try:
            resp = self.opener.open(req)
            return self.deserialize_job(resp.read())
        except urllib2.HTTPError as e:
            if e.code == 404:
                return None
            else:
                raise e

    def commit_job_batch(self, job_batch):
        """
        Send the given batch to the gateway
        ARGS:
            job_batch - an iterable of JobTuples or tuples of (priority num, JobTuple)

        RETURNS status code
        """
        serialized_batch = []
        for job_tuple in job_batch:
            if isinstance(job_tuple, JobTuple):
                #We set our priority number as the expiration time in epoch for a particular job
                priority_number = str(int(mktime(job_tuple.create_time.timetuple())) + int(job_tuple.expiration_period))
                serialized_batch.append(priority_number + ":" + self.serialize_job(job_tuple))
            elif isinstance(job_tuple, tuple) and len(job_tuple) == 2:
                #We set our priority number as the passed priority number in the tuple
                serialized_batch.append(str(job_tuple[0]) + ":" + self.serialize_job(job_tuple[1]))
            else:
                raise TypeError(
                    "Unexpected type=%s and size inside job_batch, expected either JobTuple or tuple of form (priority, JobTuple)" % type(
                        job_tuple))

        batch_body = "\n".join(serialized_batch)
        req = urllib2.Request(self.gateway_uri + "/hydra/job/batch", data=batch_body)
        try:
            resp = self.opener.open(req, timeout=60)
            return resp.code
        except urllib2.HTTPError as e:
            return e.code

    #Job Parsing:
    def _convert_iso_datetime(self, val):
        """
        Shameless theft of the ISODateTimeField's string parsing
        """
        if not isinstance(val, datetime.datetime):
            try:
                return datetime.datetime.strptime(val, '%Y-%m-%dT%H:%M:%S.%f')
            except TypeError:
                #if there is nothing, e.g. constructing a new item, we get TypeError
                return datetime.datetime.fromtimestamp(0)
            except ValueError:
                #support timestamps without fractional seconds
                return datetime.datetime.strptime(val, '%Y-%m-%dT%H:%M:%S')
        else:
            return val.isoformat()

    def _parse_special(self, val):
        """
        Python Object Field parsing for one part of the job tuple
        """
        if isinstance(val, str):
            try:
                obj = cPickle.loads(b64decode(val))
                return obj
            except TypeError:
                return dict()
        elif isinstance(val, dict):
            return val
        else:
            return dict()

    def _dump_special(self, val):
        """
        Python Object Field parsing for one part of job Tuple
        """
        if not isinstance(val, str):
            return b64encode(cPickle.dumps(val))
        else:
            return val

    def serialize_job(self, job_tuple):
        """
        Serialize the given job_tuple object to a string.
        """
        if isinstance(job_tuple, JobTuple):
            return "|".join([job_tuple.name, job_tuple.target, job_tuple.task, job_tuple.metadata_id,
                             self._convert_iso_datetime(job_tuple.create_time),
                             self._convert_iso_datetime(job_tuple.last_time), str(job_tuple.expiration_period),
                             self._dump_special(job_tuple.special)])
        else:
            raise TypeError("Values of hydra job fields must be namedtuples of type JobTuple")

    def deserialize_job(self, job_string):
        """
        Deserialize the given string representation of a JobTuple type into a JobTuple
        """
        if isinstance(job_string, str):
            prop_list = job_string.split("|", 7)
            if len(prop_list) == 8:
                return JobTuple(
                    prop_list[0],
                    prop_list[1],
                    prop_list[2],
                    prop_list[3],
                    self._convert_iso_datetime(prop_list[4]),
                    self._convert_iso_datetime(prop_list[5]),
                    prop_list[6],
                    self._parse_special(prop_list[7])
                )
            else:
                raise ValueError(
                    "Jobs must be of format <name>|<target>|<task>|<metadata-id>|<create_time>|<last_time>|<expiration_period(seconds)>|<special>, i.e. 8 values")
        else:
            raise TypeError(
                "Serialized jobs must be strings of the form <name>|<target>|<task>|<metadata-id>|<create_time>|<last_time>|<expiration_period(seconds)>|<special>, i.e. 8 values")

    #Test endpoint wrappers:
    def call_test_static(self):
        """
        Makes a call to the /test/static endpoint of the hydra gateway
        """
        req = urllib2.Request(self.gateway_uri + "/test/static")
        resp = self.opener.open(req)
        return resp.read()

    def call_test_echo(self, data):
        """
        Makes a call to the /test/echo endpoint of the hydra gateway
        passing in the data passed to this method
        """
        req = urllib2.Request(self.gateway_uri + "/test/echo", data=data)
        resp = self.opener.open(req)
        return resp.read()