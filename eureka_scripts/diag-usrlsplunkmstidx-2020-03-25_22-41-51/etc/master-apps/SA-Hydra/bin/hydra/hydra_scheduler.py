# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
#CORE PYTHON IMPORTS
import sys
import os
import time
import datetime
import math
import logging
from httplib2 import ServerNotFoundError
#Splunk Python does not bundle UUID, so we've included it in the hydra bin, but it is a core python module
import uuid

#CORE SPLUNK IMPORTS
import splunk
from splunk.util import normalizeBoolean
from splunk.rest import simpleRequest
import splunk.auth as auth
import splunk.entity as en
import splunk.version as ver

#SA-HYDRA IMPORTS
from hydra import XMLOutputManager, setupLogger, isSplunkSessionKeyValid, ForceHydraRebuild
from models import HydraHealthStanza, HydraMetadataStanza, HydraNodeStanza, SplunkStoredCredential, HydraGatewayStanza
from hydra_common import HydraCommon, HydraGatewayAdapter, JobTuple
#Modify Path to include SA-VMNetAppUtils/bin
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-VMNetAppUtils', 'lib']))
from SolnCommon.modinput import ModularInput, Field, DurationField

#Utility Functions
def makeFieldID():
    """
    Return a string usable as an id in a splunk wildcard field
    """
    return str(uuid.uuid1()).replace("-", "")


#Classes for data, might want to put these in a module by themselves at some point
class HydraConfigToken(object):
    """A config token that can be sent to any worker."""

    def __init__(self, target, username, task, metadata_id, logger, initial_schedule_offset=0, metadata={}, special={},
                 initial_aggregate_execution_time=5):
        """
        Task and Target are the job type to perform and the target host to perform
        it on.

        ARGS:
        @type target: str
        @param target: The external system/resource upon which to perform the task
        @type username: str
        @param username: The username to use when logging into the target
        @type task: str
        @param task: The task or type of job to perform on the target
        @type metadata_id: str
        @param metadata_id: the name of the metadata to use when performing the task
        @type logger: logging.logger reference
        @param logger: the logger to use when writing out messages to the scheduler log
        @type initial_schedule_offset: int
        @param initial_schdule_offset: the delta from the current time at which to begin scheduling jobs from this config token
        @type metadata: dict
        @param metadata: the collection configuration information for this particular config token to determine the scheduling properties
        @type special: dict
        @param special: the metadata specific to this config token only that will be stored in the job tuple
        @type initial_aggregate_execution_time: int
        @param initial_aggregate_execution_time: the inital weight of jobs created by this config token
        """
        #Basic stuff
        self.target = target
        self.username = username
        self.task = task
        self.logger = logger
        self.metadata_id = metadata_id
        self.special = special
        # read default offset from config if exits
        if task + "_offset" in metadata:
            self.offset = metadata[task + "_offset"]
        else:
            self.offset = initial_schedule_offset

        self.metadata = metadata

        #Handle all work around scheduling this thing
        interval_param_name = task + "_interval"
        if interval_param_name in metadata:
            self.interval = metadata[interval_param_name]
        else:
            self.logger.error(
                "Could not establish configured interval for job type %s, setting to default of 60 seconds", self.task)
            self.interval = 60
        #Expiration period
        expiration_param_name = task + "_expiration"
        if expiration_param_name in metadata:
            self._expiration_period = metadata[expiration_param_name]
        else:
            self.logger.error(
                "Could not establish configured expiration period for job type %s, setting to default of same as interval",
                self.task)
            self._expiration_period = self.interval

        #Priority Modification
        priority_param_name = task + "_priority"
        if priority_param_name in metadata:
            self._priority_adjustment = metadata[priority_param_name]
            self.logger.debug("Established configured priority adjustment for job type %s, setting to %s", self.task,
                              self._priority_adjustment)
        else:
            self.logger.debug(
                "Could not establish configured priority adjustment for job type %s, setting to default of 0",
                self.task)
            self._priority_adjustment = 0

        #Task execution initial estimated time
        task_exec_param_name = task + "_exectime"
        if task_exec_param_name in metadata:
            self._execution_time = metadata[task_exec_param_name]
            self.logger.debug("Established configured execution time for job task=%s, setting to %s", self.task,
                              self._execution_time)
        else:
            self.logger.debug("Could not establish configured execution time for job task=%s, setting to default %s",
                              self.task, initial_aggregate_execution_time)
            self._execution_time = initial_aggregate_execution_time

        #Atomic Task Handling
        self._assigned = False
        confirmation_expiration_param_name = task + "_confirmation_expiration"
        if confirmation_expiration_param_name in metadata:
            self._confirmation_expiration = metadata[confirmation_expiration_param_name]
            self.logger.debug(
                "Established configured atomic confirmation expiration period for job task=%s, setting to %s",
                self.task, self._confirmation_expiration)
        else:
            self._confirmation_expiration = 2 * self.interval
            self.logger.debug(
                "Could not establish configured atomic confirmation expiration period for job task=%s, setting to default of 2*interval, %s",
                self.task, self._confirmation_expiration)
        # assignment_info is only used for atomic completion or failure tracking
        self.assignment_info = None
        if task in metadata.get("atomic_tasks", []):
            self.atomic = True
        else:
            self.atomic = False

        self._parse_time = datetime.datetime.utcnow()
        self._schedule_time = self._parse_time + datetime.timedelta(seconds=self.offset)
        self._last_time = self._parse_time

        #This is used to know who to preferably assign this particular job to
        self.worker_affinity = []

    def __str__(self):
        """
        Return the job type, username, and target as representation for this config token

        RETURNS string representation of this config token
        """
        return "HydraConfigToken(task={0}, target={1}, username={2})".format(self.task, self.target, self.username)

    def __repr__(self):
        """
        Return the job type, username, and target as representation for this config token

        RETURNS string representation of this config token
        """
        return "HydraConfigToken(task={0}, target={1}, username={2})".format(self.task, self.target, self.username)

    def getExecTime(self):
        '''
        @return: return execution time for token
        '''
        return self._execution_time

    def setExecTime(self, time_in_sec):
        '''
        @param time_in_sec: execution time in sec
        @return: nothing
        '''
        self._execution_time = time_in_sec

    def setOffset(self, initial_offset=0):
        '''
            Set initial token offset
            @param initial_offset: offset value in sec
            @return: nothing
        '''
        self.offset = initial_offset
        self.logger.info("Successfully set offset for task=%s, target=%s, offset=%s", self.task, self.target,
                         self.offset)
        #updating schedule time
        self._schedule_time = self._parse_time + datetime.timedelta(seconds=self.offset)
        self.logger.info("Schedule time is updated successfully for task=%s, target=%s, offset=%s", self.task,
                         self.target, self.offset)

    def is_locked(self):
        """
        Essentially an accessor for the _assigned prop currently, this method
        returns an boolean indicating if this config token is currently locked,
        i.e. blocked from creating jobs.

        @rtype: bool
        @return: True if locked, False if unlocked
        """
        return self._assigned

    def unlock(self):
        """
        This method is used to reset the _assigned prop to False after the
        confirmation of an atomic job's completion or expiration of the
        confirmation period. If the job is past its current scheduled time,
        resets the clock to schedule as of now.

        @rtype: None
        @return: None
        """
        self._assigned = False
        utc_now = datetime.datetime.utcnow()
        if self._schedule_time < utc_now:
            self._schedule_time = utc_now

    def isReady(self):
        """
        Determine if this task is ready to be scheduled.
        Note for continuous tasks this is a mapping to whether or not the task is assigned.

        @rtype: bool
        @return True if ready to be assigned, False if not time yet
        """
        should_be_ready = self._schedule_time <= datetime.datetime.utcnow()
        if not self.atomic:
            return should_be_ready
        else:
            if not self._assigned:
                return should_be_ready
            #Determine if we should auto unlock due to lack of notification in time
            elif (self._schedule_time + datetime.timedelta(
                    seconds=self._confirmation_expiration)) <= datetime.datetime.utcnow():
                if self.assignment_info is not None:
                    node_path, job_name = self.assignment_info
                else:
                    node_path, job_name = ("UNKNOWN", "UNKNOWN")
                self.logger.warning(
                    "[HydraConfigToken] [isReady] atomic config_token=%s failed to confirm execution of last assigned job=%s on node=%s within confirmation_expiration, unlocking job and allowing assignment...",
                    str(self), job_name, node_path)
                self.unlock()
                return should_be_ready
            else:
                #we are locked and should be locked
                if self.assignment_info is not None:
                    node_path, job_name = self.assignment_info
                else:
                    node_path, job_name = ("UNKNOWN", "UNKNOWN")
                self.logger.debug(
                    "[HydraConfigToken] [isReady] atomic config_token=%s not yet to confirm execution of last assigned job=%s on node=%s, blocking job creation",
                    str(self), job_name, node_path)
                return False


    def scheduleNext(self):
        """
        Schedule the next iteration of this particular config token This follows several rules.
        At the most basic it adds its interval to the current schedule time and sets it. It will
        however only do so if that time is in the future, if not it will continue to add the
        interval until it is in the future flagging a warning each time.

        @rtype: None
        """
        if self.interval < 1:
            return
        schedule_time = self._schedule_time
        self._last_time = schedule_time
        cur_time = datetime.datetime.utcnow()
        while True:
            schedule_time += datetime.timedelta(seconds=self.interval)
            if schedule_time > cur_time:
                self._schedule_time = schedule_time
                if not self.atomic:
                    self._assigned = False
                break
            else:
                self.logger.warning(
                    "config token type {0} has missed one iteration due at {1}, scheduling for next iteration with interval {2}".format(
                        self.task, str(schedule_time), str(self.interval)))

    def _updateAffinity(self, worker_path):
        """
        Update self.worker_affinity to reflect the assignment of this job to this node.
        args:
            worker_path - the management uri of the worker to update the affinity for

        RETURNS nothing
        """
        try:
            self.worker_affinity.remove(worker_path)
        except ValueError:
            self.logger.debug("[HydraConfigToken] first time instance of config_token=%s assigned to worker=%s",
                              str(self), worker_path)
        self.worker_affinity.insert(0, worker_path)

    def register_assignment(self, job_name, node_path):
        """
        Take note of the job name and the worker the job was assigned to so that
        we can unlock the job once it completes.

        @type job_name: str
        @param job_name: the name/id of the assigned job
        @type node_path: str
        @param node_path: the data collection node's node_path to which the job was assigned

        @rtype: None
        @return: None
        """
        #Assignment info is the simple tuple of the node_path and the job_name as assigned to that worker
        self.assignment_info = (node_path, job_name)

    def assignToWorker(self, worker):
        """
        Give this a worker's HydraWorkerNode object and it will assign it's current job
        with the correct information to the specified worker.
        If successfully assigned this will also mark this config token as assigned.

        returns True if successful, False if not
        """
        job_name = "job_" + makeFieldID()
        job = JobTuple(job_name, self.target, self.task, self.metadata_id, self._schedule_time, self._last_time,
                       self._expiration_period, self.special)
        priority_num = str(
            int(time.mktime(job.create_time.timetuple())) + int(job.expiration_period + self._priority_adjustment))
        if worker.addJob((priority_num, job), self, self.atomic):
            self._updateAffinity(worker.node_path)
            self._assigned = True
            self.scheduleNext()
            self.logger.debug("[HydraConfigToken] job=%s of task=%s queued for assignment to node=%s", job_name,
                              self.task, worker.node_path)
            return True
        else:
            self.logger.error("[HydraConfigToken] job=%s of task=%s failed to be assigned to node=%s", job_name,
                              self.task, worker.node_path)
            return False


class HydraCollectionManifest(object):
    """
    An administration layer on top of collections of config tokens aimed at data
    collection.
    An instance of this class provides scheduling methods for its constituent tasks
    """

    def __init__(self, logger, metadata_dict={}, config_token_list=[], app="SA-Hydra"):
        """
        Create a new instance of a collection manifest, optionally with a config
        token list specified.
        """
        self._metadata_dict = metadata_dict
        self._config_token_list = config_token_list
        self.logger = logger
        self.app = app
        # Dict which hold aggregate execution time taken by task level
        # Key is task, value is tuple of execution time, by total execution cycles far
        self.task_aggre_exec_time = {}
        # Dict to hold aggregate execution time taken by task, target, meta_data_id
        # Key is combination of target|task|meta_id, value is tuple of execution time, by total execution cycles so far
        self.task_target_metaid_aggre_exec_time = {}

        self._calculateTokenListProperties()
        self._calculateExecutionTime()

    def _calculateTokenListProperties(self):
        """
        Recalculates all internal properties based on the token list including:
            task_set - a set of all distinct tasks in the manifest
            atomic_config_tokens - a list of all config tokens that are marked atomic

        returns nothing
        """
        self.task_set = set()
        self.atomic_config_tokens = []
        for token in self._config_token_list:
            self.task_set.add(token.task)
            if token.atomic:
                self.atomic_config_tokens.append(token)
        self.logger.debug("[HydraCollectionManifest] calculated aggregated collection task_set=%s", self.task_set)

    def _calculateExecutionTime(self):
        '''
            Calculate initial execution time at task and target|task|metadata_id level
            @return: nothing
        '''
        for token in self._config_token_list:
            key = token.task
            value = [float(token.getExecTime()), 1]
            self._update_execution_dict(self.task_aggre_exec_time, key, value)
            # update at target, task and metadata id level
            key = token.target + "|" + token.task + "|" + token.metadata_id
            self._update_execution_dict(self.task_target_metaid_aggre_exec_time, key, value)

    def _calculateTaskWeights(self, node_list):
        """
        Given a particular node list calculate the weights of all tasks
        and return them as a dict
        """
        weights = {}
        for task in self.task_set:
            weight = 0
            for node in node_list:
                if node.hasCapability(task):
                    weight += node.model.heads
            self.logger.debug("[HydraCollectionManifest] calculated weight=%s for task=%s", weight, task)
            if weight == 0:
                self.logger.error(
                    "[HydraCollectionManifest] calculated weight=%s for task=%s implies no node will be able to perform jobs of this task, please alter capabilities of your nodes to accommodate this task",
                    weight, task)
            weights[task] = weight

        return weights

    def getReadyJobs(self):
        """
        gets a list of jobs ready to assign

        returns list of jobs ready to be assigned
        """
        ready_jobs = []
        for token in self._config_token_list:
            if token.isReady():
                ready_jobs.append(token)
        return ready_jobs

    def getTimeToNextJob(self):
        """
        Get the time in seconds until the next job is ready to be scheduled

        RETURNS time in seconds
        """
        time_to_next_job = None
        utc_now = datetime.datetime.utcnow()
        token_delta = 0
        for token in self._config_token_list:
            if utc_now > token._schedule_time:
                token_delta = 0
            else:
                token_delta = (token._schedule_time - utc_now).seconds
            if time_to_next_job is None:
                time_to_next_job = token_delta
            elif token_delta < time_to_next_job:
                time_to_next_job = token_delta
        if time_to_next_job is None:
            raise ForceHydraRebuild(
                "[HydraCollectionManifest] could not establish the time to next job run, forcing a rebuild...")
        return time_to_next_job

    def _update_execution_dict(self, dict_var, key, value):
        '''
            Support function to update task_aggre_exec_time or task_target_metaid_aggre_exec_time

            @param dict_var : dict reference of one of them (task_aggre_exec_time or task_target_metaid_aggre_exec_time)
            @key : key name which needs to be updated (target|task|metadata_id)
            @value : Array of 2 items,
                0 - Average value of give count in 1 index
                1 - Number of cycles execution time reported for given key
            @return nothing
        '''
        if dict_var.has_key(key):
            total_cycle = dict_var[key][1] + value[1]
            # Avoid divide by zero exception
            if total_cycle > 0:
                dict_var[key] = (
                (float(dict_var[key][0] * dict_var[key][1] + value[0] * value[1])) / total_cycle, total_cycle)
        else:
            dict_var[key] = (value[0], value[1])
        # check if dict value reached hit float max threshold
        if dict_var[key][0] / sys.float_info.max > 0.85:
            # reset it to 20% of the current value
            self.logger.info(
                "[HydraCollectionManifest] Float value has reached to 85% of max float so reseting it to 20% of the current value")
            dict_var[key][0] = 0.2 * dict_var[key][0]

    def _update_execution_time(self, info_dict):
        '''
         Update aggregated execution in task_aggre_exec_time, task_target_metaid_aggre_exec_time

         @param info_dict: dict which has avg execution time reported by gateway
        '''
        for key, value in info_dict.iteritems():
            # Update for target|task|metadata_id
            self._update_execution_dict(self.task_target_metaid_aggre_exec_time, key, value[:2])
            # Update for task
            self._update_execution_dict(self.task_aggre_exec_time, key.split("|")[1], value[:2])

    def _get_job_avg_exectime(self, key, task):
        '''
            Get avg execution from task_aggre_exec_time or task_target_metaid_aggre_exec_time

            @return: avg execution time in float if exists otherwise 0.0
        '''
        if self.task_target_metaid_aggre_exec_time.has_key(key):
            # Get target, task and metadata_id level if this is defined
            return float(self.task_target_metaid_aggre_exec_time[key][0])
        else:
            # Get a task level (Assuming that task level this value is always be defined)
            if self.task_aggre_exec_time.has_key(task):
                return float(self.task_aggre_exec_time[task][0])
            else:
                # This code will not execute ever however if any case lets log the information
                self.logger.error(
                    "[HydraCollectionManifest] Could not find execution time so skipping job to calculate the average execution time  (key=%s)",
                    key)
                return 0.0

    def _calculateLoadDistribution(self, node_list, ready_jobs, node_job_infos):
        """
        This method takes in a node_list and ready jobs and
        calculates the load balance information. This load balance information
        is represented by available_work_load which is a mapping of host path
        to the number of load that node has to put work in.
            @param node_list: a list of active HydraWorkerNode objects
            @param read_jobs: jobs that need to be scheduled
            @param node_job_infos: dict of aggregate job execution info which is reported by gateway from all
                            workers node (see getActiveJobInfo for details)

            @return:  tuple of available_work_load, balanced_load of each head
                        available_work_load is a dict which hold work load which can be handle by each worker
                        key of this dict is a worker path
                        balance_load : load of per worker head
        """
        #Must use floats due to division
        head_count = 0.0
        queue_job_execution_time = {}
        available_work_load = {}
        for worker in node_list:
            node_job_info = node_job_infos[worker.node_path]
            self.logger.debug("[HydraCollectionManifest] Average time reported by gateway of node=%s, value=%s",
                              worker.node_path, node_job_info)
            # Update execution time at task and target|task|metadata_id and task level
            self._update_execution_time(node_job_info["job_aggregate_execution_info"])
            # calculate unclaimed job execution time
            total_unclaimed_queue_execution_time = 0.0
            for key, value in node_job_info["job_aggregate_execution_info"].iteritems():
                total_unclaimed_queue_execution_time = total_unclaimed_queue_execution_time + value[
                                                                                                  2] * self._get_job_avg_exectime(
                    key, key.split("|")[1])  # active jobs * avg time
            queue_job_execution_time[worker.node_path] = total_unclaimed_queue_execution_time
            self.logger.debug(
                "[HydraCollectionManifest] node=%s current unclaimed queue length=%s, left execution time=%s",
                worker.node_path, node_job_info["count"], total_unclaimed_queue_execution_time)
            head_count += worker.model.heads
        # calculate ready queue execution time
        total_readyqueue_execution_time = 0.0
        for ready_job in ready_jobs:
            total_readyqueue_execution_time = total_readyqueue_execution_time + self._get_job_avg_exectime(
                key=ready_job.target + "|" + ready_job.task + "|" + ready_job.metadata_id, task=ready_job.task)

        balanced_load = math.ceil((total_readyqueue_execution_time + total_unclaimed_queue_execution_time) / head_count)
        self.logger.debug(
            "[HydraCollectionManifest] spraying jobs to %s heads on %s nodes with balanced unclaimed queue load per head of %s",
            head_count, len(node_list), balanced_load)
        for worker in node_list:
            available_work_load[worker.node_path] = balanced_load * worker.model.heads - queue_job_execution_time[
                worker.node_path]
            self.logger.debug("[HydraCollectionManifest] node=%s load balanced available work load=%s",
                              worker.node_path, available_work_load[worker.node_path])
        return available_work_load, balanced_load

    def _queueJobsToWorkers(self, job_list, node_list, available_work_load, node_manifest, balanced_load, node_infos):
        """
        Given a list of sorted jobs and a list of active HydraWorkerNode objects
        this will queue all jobs to the workers. This uses the load balance info
        in available_work_load and the workers_by_path dict.
        Honestly is this method particularly useful isolated? No. But we make
        sillyness for the sake of being able to unit test.
        ARGS:
            job_list - list of HydraConfigToken objects to be queued
            node_list - list of HydraWorkerNode objects onto which to queue jobs
            available_work_load - mapping of available load per node (see
                _calculateLoadDistribution for details)
            node_manifest - the node manifest to which all these nodes belong
            balance_load - Load balancer value ( see _calculateLoadDistribution for details)
            node_infos - is a dict which hold reported by gateway from each worker

        RETURNS nothing
        """
        worker_queue_load_sort_key = lambda worker: available_work_load[worker.node_path]
        workers_by_path = node_manifest.nodes_by_path
        # Define minimum jobs count as per head count and considering existing job count on that node
        minimum_job = {}
        for node in node_list:
            minimum_job[node.node_path] = node.model.heads - node_infos[node.node_path]["count"]

        for token in job_list:
            worker_path = None
            worker = None
            avg_job_exec_time = self._get_job_avg_exectime(
                key=token.target + "|" + token.task + "|" + token.metadata_id, task=token.task)
            #First check the by token affinity
            for tmp_path in token.worker_affinity:
                if (available_work_load.get(tmp_path, 0) - avg_job_exec_time) > 0 or minimum_job.get(tmp_path, 0) > 0:
                    tmp_worker = workers_by_path[tmp_path]
                    if tmp_worker.hasCapability(token.task):
                        worker_path = tmp_path
                        worker = tmp_worker
                        self.logger.debug("Assigned job based upon job token affinity for node=%s  node_path=%s",
                                          worker, worker_path)
                        break

            #If that fails, check the by target affinity
            if worker_path is None:
                for tmp_path in node_manifest.getPreferredNodesForTarget(token.target):
                    if (available_work_load.get(tmp_path, 0) - avg_job_exec_time) > 0 or minimum_job.get(tmp_path,
                                                                                                         0) > 0:
                        tmp_worker = workers_by_path[tmp_path]
                        if tmp_worker.hasCapability(token.task):
                            worker_path = tmp_path
                            worker = tmp_worker
                            self.logger.debug("Assigned job based upon job target affinity for node=%s  node_path=%s",
                                              worker, worker_path)
                            break

            #If that fails, just assign to a worker that has the best room(Start filling form smallest available load)
            if worker_path is None:
                node_list.sort(key=worker_queue_load_sort_key)
                for node in node_list:
                    if node.hasCapability(token.task):
                        # First best fit node
                        if available_work_load[node.node_path] - avg_job_exec_time > 0 or minimum_job[
                            node.node_path] > 0:
                            worker = node
                            worker_path = node.node_path
                            self.logger.debug(
                                "Assigned job based upon job first best fit algorithm for node=%s  node_path=%s",
                                worker, worker_path)
                            break

            #If thats fails, (may be a corner case where sum of all available weight is greater than that job execution time, but individual node does not have enough load factor left out)
            if worker_path is None:
                node_list.sort(key=worker_queue_load_sort_key, reverse=True)
                for node in node_list:
                    worker = node
                    worker_path = worker.node_path
                    if worker.hasCapability(token.task):
                        self.logger.debug("Assigned job based upon job weight for node=%s  node_path=%s", worker,
                                          worker_path)
                        break
                else:
                    self.logger.error(
                        "[HydraCollectionManifest] unable to find an active node capable of executing config_token=%s of task=%s if no node configured for this task becomes active this config_token will never generate another job",
                        token, token.task)
                    worker = None
                    continue

            #Queue up the job to the node for assignment to its gateway queue
            if worker is not None and token.assignToWorker(worker):
                node_manifest.updateTargetNodeAffinity(token.target, worker_path)
                self.logger.debug(
                    "Before job assignment values are, node_weight=%s, job_weight=%s, minimum_job(can be negative value)=%s",
                    available_work_load[worker_path], avg_job_exec_time, minimum_job[worker_path])
                available_work_load[worker_path] = available_work_load[worker_path] - avg_job_exec_time
                minimum_job[worker_path] = minimum_job[worker_path] - 1
                self.logger.debug(
                    "After job assignment value, node_weight=%s, job_weight=%s, minimum_job(can be negative value)=%s",
                    available_work_load[worker_path], avg_job_exec_time, minimum_job[worker_path])


    def _unlock_atomic_jobs(self, node_job_infos):
        """
        Given the job infos from the active nodes attempt to unlock all the
        atomic config tokens that are currently locked. This is done by
        matching the completed jobs against the atomic config token's stored
        current job. If a node is not present that an atomic config token
        previously assigned to and expects to hear from we flag a warning but
        do not try to reassign unless the config token lock is expired.

        @type node_job_infos: dict
        @param node_job_infos: the dict of node -> job info

        @rtype None
        @return None
        """
        for config_token in self.atomic_config_tokens:
            if config_token.is_locked():
                node_path, job_name = config_token.assignment_info
                if node_path in node_job_infos:
                    node_job_info = node_job_infos[node_path]
                    node_atomic_job_info = node_job_info.get("atomic_job_info",
                                                             {"completed_atomic_jobs": [], "failed_atomic_jobs": []})
                    if job_name in node_atomic_job_info.get("completed_atomic_jobs", []):
                        config_token.unlock()
                        self.logger.debug(
                            "[HydraCollectionManifest] [UnlockAtomicJobs] confirmed completion of job=%s on node=%s originating from token=%s",
                            job_name, node_path, config_token)
                    elif job_name in node_atomic_job_info.get("failed_atomic_jobs", []):
                        config_token.unlock()
                        self.logger.error(
                            "[HydraCollectionManifest] [UnlockAtomicJobs] confirmed the failure of job=%s on node=%s originating from token=%s",
                            job_name, node_path, config_token)
                    else:
                        self.logger.debug(
                            "[HydraCollectionManifest] [UnlockAtomicJobs] unable to confirm completion/failure of job=%s on node=%s originating from token=%s with current execution information",
                            job_name, node_path, config_token)

    def _getActiveWorkerInfo(self, node_manifest, confirm_status=True):
        """
        Refresh Nodes and set new dict of active workers for scheduler run
        @type confirm_status: bool
        @param confirm_status: whether to confirm status by calling updateStatus 

        @rtype dict
        @return active_workers
        """
        node_manifest.refreshNodes(confirm_status)
        active_workers = node_manifest.active_nodes
        worker_count = len(active_workers)
        if worker_count < 1:
            self.logger.error(
                "[HydraCollectionManifest] Attempted to assign jobs but we have no active workers to assign to. Restarting Scheduler...")
            raise ForceHydraRebuild

        return active_workers

    def sprayReadyJobs(self, node_manifest):
        """
        Take all config tokens that are ready to be assigned out as jobs and spray them over
        active workers in efforts to even out job queues.
        This method will also be in charge of managing affinities for workers to particular
        target assets.

        args:
            node_manifest - the node manifest to get the worker nodes to assign the jobs to from
        """
        #Get workers
        active_workers = self._getActiveWorkerInfo(node_manifest)

        #Get aggregate job execution information
        node_job_infos = {}
        for worker in active_workers:
            activeJobInfo = worker.getActiveJobInfo()
            #No active job found for this node
            if len(activeJobInfo) > 0:
                node_job_infos[worker.node_path] = activeJobInfo
        
        #Need refreshNodes again in case node statuses are changed while getting active job
        active_workers = self._getActiveWorkerInfo(node_manifest, False)

        #Unlock atomic jobs here based on the node_job_infos
        self._unlock_atomic_jobs(node_job_infos)

        #Sort jobs by task weight primarily so that the hardest to schedule get scheduled first, secondarily by target
        task_weights = self._calculateTaskWeights(active_workers)
        ready_jobs = self.getReadyJobs()
        ready_jobs.sort(key=lambda token: token.target)
        ready_jobs.sort(key=lambda token: task_weights[token.task])
        self.logger.debug("Sorted list of ready_jobs=%s", ready_jobs)

        #Calculate load balancing
        available_work_load, balanced_load = self._calculateLoadDistribution(active_workers, ready_jobs, node_job_infos)

        #Spray the jobs onto workers
        self._queueJobsToWorkers(ready_jobs, active_workers, available_work_load, node_manifest, balanced_load,
                                 node_job_infos)

        #Now that we have established the assignments, we actually commit the queues
        reassign_jobs = []
        atomic_reassign_jobs = {}
        for worker in active_workers:
            try:
                failed_to_assign, atomic_failed_to_assign = worker.commitJobs()
                reassign_jobs += failed_to_assign
                atomic_reassign_jobs.update(atomic_failed_to_assign)
            except Exception:
                self.logger.exception(
                    "[HydraCollectionManifest] failed to assign batch of jobs for node=%s, may be dead and reassigning jobs to others, may cause job duplication",
                    worker.node_path)
                reassign_jobs += (worker.add_jobs)
                worker.add_jobs = []

        if reassign_jobs != []:
            #call primitive sprayJobSet that sprays already parsed jobs.
            node_manifest.sprayJobSet(reassign_jobs, atomic_reassign_jobs)


class HydraWorkerNode(object):
    '''
    An object representation of a splunk forwarder running at least 1 HydraWorker process
    and added to this scheduler's management in hydra_node.conf
    '''
    #Class variables for use in status
    OFFLINE = False
    ONLINE = True

    def __init__(self, logger, path, password, model, gateway_uri, session_key=None, metadata_dict=None,
                 worker_input_name="ta_vmware_collection_worker"):
        """
        Initialize the HydraWorkerNode object.
        args:
            logger - a ref to a logger instance
            path - this is the management uri (host_path) to this splunk server, e.g. https://forwarder.splunk.com:8089
            password - the splunkd management service password for the node
            model - this is the HydrasNodeStanza model object corresponding to this node
            gateway_uri - this is the uri for the Hydra WSGI Gateway on the node, e.g. https://forwarder.splunk.com:8008
            session_key - this is the valid session_key for this splunk forwarder
            worker_input_name - the name of the modular input to control worker processes
        """
        self.logger = logger
        self.node_path = path
        self.model = model
        self.app = self.model.namespace
        self.password = password
        self.worker_input_name = worker_input_name
        self.gateway_uri = gateway_uri
        self.capabilities = self.model.capabilities if self.model.capabilities is not None else ["*"]
        self.worker_log_level = self.model.log_level if self.model.log_level is not None else "INFO"

        #Establish the session key and the status
        if session_key is None:
            self.refreshSessionKey()
        else:
            self.session_key = session_key
            self.updateStatus()

        self.configureGateway()

        self.establishGateway()

        if metadata_dict is not None:
            self.setMetadata(metadata_dict, bounce_heads=False)

        self.heads_list = self.establishHeads()
        self.add_jobs = []
        self.atomic_add_jobs = {}

    def hasCapability(self, task):
        """
        Check that this node can perform the given task
        ARGS:
            task - the task to check

        RETURNS True if it can, False otherwise
        """
        if "*" in self.capabilities or task in self.capabilities:
            return True
        else:
            return False

    def configureGateway(self):
        """
        Configure the gateway on the node per the hydra_node configuration
        """
        self.logger.info(
            "[HydraWorkerNode] [configureGateway] setting gateway configuration on node=%s to bind to port=%s...",
            self.node_path, self.model.gateway_port)
        try:
            stanza = HydraGatewayStanza.from_name("gateway", "SA-Hydra", host_path=self.node_path,
                                                  session_key=self.session_key)
            if not stanza:
                stanza = HydraGatewayStanza("SA-Hydra", "nobody", "gateway", sessionKey=self.session_key,
                                            host_path=self.node_path)
            stanza.port = self.model.gateway_port
            for retry in range(4):
                if stanza.passive_save():
                    self.logger.info("[HydraWorkerNode] [configureGateway] successfully configured gateway on node=%s",
                                     self.node_path)
                    break
            else:
                self.logger.error(
                    "[HydraWorkerNode] [configureGateway] failed to configure gateway on node=%s after %s retries",
                    self.node_path, retry)
                #mark this guy offline since we can't configure it remotely
                self.status = HydraWorkerNode.OFFLINE
        except Exception as e:
            self.logger.exception(
                "[HydraWorkerNode] [configureGateway] problem configuring gateway, marking node dead: %s", str(e))
            self.status = HydraWorkerNode.OFFLINE

    def establishGateway(self):
        """
        Safely establish the adapter to the hydra gateway on the node. If it
        cannot be established mark the node dead and set it to None.
        """

        hga = None
        self.logger.info("[HydraWorkerNode] [establishGateway] attempting to connect to gateway=%s for node=%s ...",
                         self.gateway_uri, self.node_path)
        try:
            hga = HydraGatewayAdapter(self.node_path, self.session_key, self.gateway_uri)
            self.logger.info("[HydraWorkerNode] [establishGateway] successfully connected to gateway=%s for node=%s",
                             self.gateway_uri, self.node_path)
        except splunk.SplunkdConnectionException:
            self.logger.error(
                "[HydraWorkerNode] [establishGateway] could not connect to gateway=%s for node=%s due to a socket error, timeout, or other fundamental communication issue, marking node as dead",
                self.gateway_uri, self.node_path)
            self.status = HydraWorkerNode.OFFLINE
        except splunk.AuthenticationFailed:
            self.logger.error(
                "[HydraWorkerNode] [establishGateway] could not authenticate with gateway=%s for node=%s due to a splunkd authentication issue, marking node as dead",
                self.gateway_uri, self.node_path)
            self.status = HydraWorkerNode.OFFLINE
        except splunk.LicenseRestriction:
            self.logger.error(
                "[HydraWorkerNode] [establishGateway] could not authenticate with gateway=%s for node=%s due to a splunkd license issue, this is fatal, marking node as dead permanently",
                self.gateway_uri, self.node_path)
            self.status = HydraWorkerNode.OFFLINE
        except splunk.AuthorizationFailed:
            self.logger.error(
                "[HydraWorkerNode] [establishGateway] could not authenticate with gateway=%s for node=%s due to a splunkd user permissions issue, this is fatal, marking node as dead permanently",
                self.gateway_uri, self.node_path)
            self.status = HydraWorkerNode.OFFLINE
        except splunk.ResourceNotFound:
            self.logger.error(
                "[HydraWorkerNode] [establishGateway] could not authenticate with gateway=%s for node=%s due to missing hydra gatekeeper EAI endpoint, this is fatal, marking node as dead permanently",
                self.gateway_uri, self.node_path)
            self.status = HydraWorkerNode.OFFLINE
        except splunk.InternalServerError as e:
            self.logger.error(
                "[HydraWorkerNode] [establishGateway] could not authenticate with gateway=%s for node=%s due to internal server error=\"%s\", marking node as dead",
                self.gateway_uri, self.node_path, str(e))
            self.status = HydraWorkerNode.OFFLINE
        except splunk.BadRequest as e:
            self.logger.error(
                "[HydraWorkerNode] [establishGateway] could not authenticate with gateway=%s for node=%s due to bad request error=\"%s\", marking node as dead",
                self.gateway_uri, self.node_path, str(e))
            self.status = HydraWorkerNode.OFFLINE
        except splunk.RESTException as e:
            self.logger.error(
                "[HydraWorkerNode] [establishGateway] could not authenticate with gateway=%s for node=%s due to some crazy REST error=\"%s\", marking node as dead",
                self.gateway_uri, self.node_path, str(e))
            self.status = HydraWorkerNode.OFFLINE
        except ServerNotFoundError as e:
            self.logger.error(
                "[HydraWorkerNode] [establishGateway] could not find gateway=%s for node=%s error=\"%s\", node will be dead permanently",
                self.gateway_uri, self.node_path, str(e))
            self.status = HydraWorkerNode.OFFLINE
        except Exception as e:
            self.logger.error(
                "[HydraWorkerNode] [establishGateway] could not authenticate with gateway=%s for node=%s due to error=\"%s\", marking node as dead",
                self.gateway_uri, self.node_path, str(e))
            self.status = HydraWorkerNode.OFFLINE

        self.gateway_adapter = hga

    def getActiveJobInfo(self):
        """
        Pulls the latest job information from the node's hydra gateway.

        @return: a dict
                key : target|task|metadata_id
                 value : is array of three items
                     0 : aggregate execution time
                     1 : number of times execution time is reported for this category
                     2 : unclaimed job count for this category
        """
        job_info = {}
        try:
            job_info = self.gateway_adapter.get_job_info()
        except Exception as e:
            self.logger.exception(
                "[HydraWorkerNode] node=%s is likely dead, could not get info on current job count, msg : %s",
                self.node_path, str(e))
            self.updateStatus(refresh_session_key=True)

        return job_info

    def __str__(self):
        """
        Print the object and the node path as a string representation for this node.
        """
        return "HydraWorkerNode(" + self.node_path + ")"

    def __repr__(self):
        """
        Print the object and the node path as a string representation for this node.
        """
        return "HydraWorkerNode(" + self.node_path + ")"

    def refreshSessionKey(self):
        """
        Attempt to refresh the session key of this node either with shared key auth or
        with username/password.

        RETURNS True if successful, False if not
        """
        session_key = None
        unrecoverable = False
        try:
            session_key = auth.getSessionKey(self.model.user, self.password, self.node_path)
        except splunk.SplunkdConnectionException:
            self.logger.error(
                "[HydraWorkerNode] node=%s is dead, could not connect to splunkd check path and if splunkd is up on remote node",
                self.node_path)
        except splunk.LicenseRestriction:
            unrecoverable = True
            self.logger.error("[HydraWorkerNode] node=%s is dead due to a license issue", self.node_path)
        except splunk.AuthorizationFailed:
            unrecoverable = True
            self.logger.error(
                "[HydraWorkerNode] node=%s is dead, could connect to splunkd but failed to auth check username and password",
                self.node_path)
        except Exception as e:
            self.logger.exception("[HydraWorkerNode] node=%s is dead, because some weird stuff happened: %s",
                                  self.node_path, str(e))

        if session_key is not None:
            self.logger.debug(
                "[HydraWorkerNode] {0} is alive, successfully authenticated user {1}".format(self, self.model.user))
            self.session_key = session_key
            self.status = HydraWorkerNode.ONLINE
            return True
        else:
            self.logger.error(
                "[HydraWorkerNode] {0} is dead, failed to authenticate user {1}".format(self, self.model.user))
            self.session_key = None
            if self.model.credential_validation and unrecoverable:
                self.logger.info("[HydraWorkerNode] node=%s is unrecoverably dead, marking so in hydra_node.conf",
                                 self.node_path)
                self.model.credential_validation = False
                if not self.model.passive_save():
                    self.logger.error("[HydraWorkerNode] failed to save credential validation as false for node=%s",
                                      self.node_path)
            self.status = HydraWorkerNode.OFFLINE
            return False
        #TODO: we need to work out the shared key auth stuff for a future release, not in chablis

    def updateStatus(self, refresh_session_key=False):
        """
        Check that this node's session key works and update it to either online or offline.
        If refresh_session_key is True attempt to refresh the session_key on a 401.
        args:
            refresh_session_key - indicates that on a 401 node should attempt to refresh session_key

        RETURNS self.status
        """
        if refresh_session_key:
            rsp_code = isSplunkSessionKeyValid(self.node_path, self.session_key, return_status=True)
            if rsp_code == 200:
                self.status = HydraWorkerNode.ONLINE
				#Also need to establish Hydra Gateway because of VMW-4355, to make Hydra Node truely ONLINE
                self.establishGateway()
            elif rsp_code == 401:
                self.logger.debug("[HydraWorkerNode] [updateStatus] detected unauthorized session key, refreshing...")
                if self.refreshSessionKey():
                    self.status = HydraWorkerNode.ONLINE
                    #If we refresh session key, we should refresh our gateway adapter as well
                    self.establishGateway()
                else:
                    self.status = HydraWorkerNode.OFFLINE
            elif rsp_code == 404:
                self.logger.debug(
                    "[HydraWorkerNode] [updateStatus] detected splunkd restart or explicit session kill, refreshing...")
                if self.refreshSessionKey():
                    self.status = HydraWorkerNode.ONLINE
                    #If we refresh session key, we should refresh our gateway adapter as well
                    self.establishGateway()
                else:
                    self.status = HydraWorkerNode.OFFLINE
            else:
                #This means something went funky so try to refresh session key
                self.logger.debug("[HydraWorkerNode] [updateStatus] could not communicate with node, refreshing...")
                if self.refreshSessionKey():
                    self.status = HydraWorkerNode.ONLINE
                    #If we refresh session key, we should refresh our gateway adapter as well
                    self.establishGateway()
                else:
                    self.status = HydraWorkerNode.OFFLINE
        else:
            if isSplunkSessionKeyValid(self.node_path, self.session_key):
                self.status = HydraWorkerNode.ONLINE
            else:
                self.status = HydraWorkerNode.OFFLINE
        if self.status == HydraWorkerNode.OFFLINE:
            self.logger.warning("[HydraWorkerNode] node=%s is offline/unresponsive/unauthenticated", self.node_path)

        return self.status

    def _toggleHead(self, head, action):
        """
        Use this method to toggle the disabled property of a particular head
        args:
            head - the name of the head
            action - either enable or disable

        returns True if successful, else False
        """
        try:
            if action not in ["enable", "disable"]:
                raise ValueError("[HydraWorkerNode] toggleHead action must be one of [enable, disable]")
            path = self.node_path.rstrip(
                "/") + "/servicesNS/nobody/" + self.app + "/data/inputs/" + self.worker_input_name + "/" + head + "/" + action
            rsp, content = simpleRequest(path, method='POST', sessionKey=self.session_key)
            if rsp.status == 200:
                return True
            else:
                self.logger.error(
                    "[HydraWorkerNode] some weird bad stuff happened trying to toggle a hydra head=%s on node=%s see content=%s",
                    head, self.node_path, str(content))
                return False
        except ValueError as e:
            raise e
        except Exception:
            self.logger.exception("[HydraWorkerNode] Problem enabling/disabling remote hydra head=%s on node=%s", head,
                                  self.node_path)
            return False

    def disableHead(self, head):
        """
        Shortcut to _toggleHead
        """
        return self._toggleHead(head, "disable")

    def enableHead(self, head):
        """
        Configure and enable a particular head on a particular node
        """
        uri = self.node_path.rstrip(
            "/") + "/servicesNS/nobody/" + self.app + "/data/inputs/" + self.worker_input_name + "/" + head
        rsp, content = simpleRequest(uri, sessionKey=self.session_key, method='POST',
                                     postargs={'capabilities': ",".join(self.capabilities),
                                               'log_level': self.model.log_level})
        if rsp.status != 200:
            self.logger.error(
                "[HydraWorkerNode] problem saving configuration for head=%s on node=%s, got status=%s with an error_response=%s",
                head, self.node_path, rsp.status, content)
        return self._toggleHead(head, "enable")

    def disableHeads(self, head_list):
        """
        Disable a list of heads

        RETURNS status boolean
        """
        status = True
        for head in head_list:
            status = status and self.disableHead(head)
        return status

    def enableHeads(self, head_list):
        """
        Enable a list of heads

        RETURNS status boolean
        """
        status = True
        for head in head_list:
            status = status and self.enableHead(head)
        return status

    def _safeSaveModels(self, *args):
        """
        Call the save on all arg'ed in items. On fails log and update status

        RETURNS nothing
        """
        if args is not None:
            for model in args:
                if not model.passive_save():
                    self.logger.error(
                        "[HydraWorkerNode] could not save %s queue and node=%s, node may be down oh monkey turds...",
                        model.name, self.node_path)
                    #verify death
                    self.updateStatus()

    def establishHeads(self):
        """
        Grab the total configured heads on the node. Normalize the enabled ones
        to match the model, or if model heads undefined define model per the remote config.
        Note that only enabled heads make it to the heads dict.

        RETURNS - a list of the names of enabled heads
        """
        #First thing is to check the status, if we are OFFLINE we return []
        enabled_heads = []
        disabled_heads = []
        if self.status != HydraWorkerNode.ONLINE:
            self.logger.info("[HydraWorkerNode] cannot establish current heads for node=%s since it is down",
                             self.node_path)
        else:
            #Now that we know we are online we need to pull all the configured heads and sort them into enabled and disabled
            configured_heads = en.getEntities("/data/inputs/" + self.worker_input_name, self.app, "nobody",
                                              sessionKey=self.session_key, hostPath=self.node_path)
            for head_name, config in configured_heads.iteritems():
                if not normalizeBoolean(config.get("disabled", True)):
                    self.logger.debug(
                        "[HydraWorkerNode] found enabled input process on node=%s with name=%s and config=%s",
                        self.node_path, head_name, config)
                    enabled_heads.append(head_name)
                else:
                    self.logger.debug(
                        "[HydraWorkerNode] found disabled input process on node=%s with name=%s and config=%s",
                        self.node_path, head_name, config)
                    disabled_heads.append(head_name)
            heads = getattr(self.model, "heads", 0)
            num_enabled_heads = len(enabled_heads)
            if num_enabled_heads == heads:
                self.logger.info("[HydraWorkerNode] Correct number of heads=%s on node=%s", heads, self.node_path)
            elif num_enabled_heads < heads:
                self.logger.error(
                    "[HydraWorkerNode] Incorrect number of heads=%s on node=%s, actual_heads=%s, trying to bring number up to correct value",
                    heads, self.node_path, num_enabled_heads)
                needed_heads = heads - num_enabled_heads
                if len(disabled_heads) >= needed_heads:
                    try:
                        new_heads_enabled = []
                        for ii in range(needed_heads):
                            head = disabled_heads[ii]
                            if self.enableHead(head):
                                new_heads_enabled.append(head)
                            else:
                                raise splunk.RESTException("Could not manage inputs on remote node=%s", self.node_path)
                        for head in new_heads_enabled:
                            enabled_heads.append(head)
                            disabled_heads.remove(head)
                    except splunk.RESTException:
                        self.logger.exception(
                            "[HydraWorkerNode] Could not manage inputs on remote node=%s, freezing heads at last configured status",
                            self.node_path)
                        #Maybe we lost connectivity to the node, we should update status
                        if self.updateStatus() == HydraWorkerNode.OFFLINE:
                            return []
                else:
                    num_disabled_heads = len(disabled_heads)
                    self.logger.error(
                        "[HydraWorkerNode] node=%s does not have enough configured input processes to match configured heads, can only enable extra %s inputs, required %s",
                        self.node_path, num_disabled_heads, needed_heads)
                    try:
                        new_heads_enabled = []
                        for ii in range(num_disabled_heads):
                            head = disabled_heads[ii]
                            if self.enableHead(head):
                                new_heads_enabled.append(head)
                            else:
                                raise splunk.RESTException("Could not manage inputs on remote node=%s", self.node_path)
                        for head in new_heads_enabled:
                            disabled_heads.remove(head)
                            enabled_heads.append(head)
                    except splunk.RESTException:
                        self.logger.exception(
                            "[HydraWorkerNode] Could not manage inputs on remote node=%s, freezing heads at last configured status",
                            self.node_path)
                        #Maybe we lost connectivity to the node, we should update status
                        if self.updateStatus() == HydraWorkerNode.OFFLINE:
                            return []
            else:
                #We have too many heads, need to disable some
                kill_count = num_enabled_heads - heads
                self.logger.error(
                    "[HydraWorkerNode] Incorrect number of heads=%s on node=%s, actual_heads=%s, trying to bring number down to correct value",
                    heads, self.node_path, num_enabled_heads)
                try:
                    new_heads_disabled = []
                    for ii in range(kill_count):
                        head = enabled_heads[ii]
                        if self.disableHead(head):
                            new_heads_disabled.append(head)
                        else:
                            raise splunk.RESTException("Could not manage inputs on remote node=%s", self.node_path)
                    for head in new_heads_disabled:
                        enabled_heads.remove(head)
                        disabled_heads.append(head)
                except splunk.RESTException:
                    self.logger.exception(
                        "[HydraWorkerNode] Could not manage inputs on remote node=%s, freezing heads at last configured status",
                        self.node_path)
                    #Maybe we lost connectivity to the node, we should update status
                    if self.updateStatus() == HydraWorkerNode.OFFLINE:
                        return []

            #Okay now we have the correct, or frozen enabled and disabled lists
            #We bounce all the heads to make sure they are actually up
            #FIXME: when we have a real interval setting for modular inputs this is not necessary (SOLNVMW-3106)
            self.disableHeads(enabled_heads)
            if not self.enableHeads(enabled_heads):
                self.logger.error(
                    "[HydraWorkerNode] Could not manage inputs on remote node=%s while bouncing heads, node is being marked offline",
                    self.node_path)
                self.status = HydraWorkerNode.OFFLINE
            if self.model.heads != len(enabled_heads):
                self.model.heads = len(enabled_heads)
                if not self.model.passive_save():
                    self.logger.error("[HydraWorkerNode] could not save hydra_node conf stanza for node=%s",
                                      self.node_path)
        return enabled_heads

    def resurrect(self):
        """
        Attempt to bring this node back to life, refreshing all internal properties

        RETURNS status boolean
        """
        self.model = self.model.from_self()
        if self.updateStatus(refresh_session_key=True) == HydraWorkerNode.ONLINE:
            self.heads_list = self.establishHeads()
            self.configureGateway()
            return True
        else:
            return False

    def checkHeadHealth(self):
        """
        Check that all heads have reported in their health status.
        If they have not reported in a health status they get bounced.

        RETURNS: nothing
        """

        #First we refresh the endpoint
        path = self.node_path.rstrip("/") + "/servicesNS/nobody/" + self.app + "/configs/conf-hydra_health/_reload"
        try:
            simpleRequest(path, sessionKey=self.session_key, raiseAllErrors=True)
        except splunk.AuthenticationFailed:
            self.logger.exception(
                "[HydraWorkerNode] could not refresh the hydra health conf for node=%s, due to auth failure, refreshing session_key...",
                self.node_path)
            self.updateStatus(refresh_session_key=True)
        except Exception as e:
            self.logger.exception("[HydraWorkerNode] could not refresh the hydra health conf for node=%s, message: %s",
                                  self.node_path, str(e))

        try:
            #Now we can iterate across logging and bouncing heads
            bounced_heads = 0
            health_stanzas = HydraHealthStanza.all(host_path=self.node_path, sessionKey=self.session_key)
            health_stanzas = health_stanzas.filter_by_app(self.app)
            health_stanzas._owner = "nobody"
            for stanza in health_stanzas:
                if stanza.head is None:
                    self.logger.warning("[HydraWorkerNode] got a bad stanza in hydra_health stanza=%s", stanza.name)
                    continue
                self.logger.error(
                    "[HydraWorkerNode] regrowing head due to sad face health problem reported for head=%s on node=%s : msg='%s'",
                    stanza.head, self.node_path, stanza.reason)
                successful = False
                already_disabled = False
                for retry in range(3):
                    if not already_disabled and not self.disableHead(stanza.head):
                        continue
                    else:
                        already_disabled = True
                        if not self.enableHead(stanza.head):
                            continue
                        else:
                            successful = True
                            break
                del retry  #just to stop the linter's whining
                if successful:
                    #Where one falls two shall grow in their place! ... err i mean one
                    self.logger.info(
                        "[HydraWorkerNode] successfully regrew head=%s on node=%s after health cry sad face",
                        stanza.head, self.node_path)
                    bounced_heads += 1
                    if not stanza.passive_delete():
                        self.logger.error(
                            "[HydraWorkerNode] could not delete health stanza for head=%s on node=%s after restart, head will likely be double restarted",
                            stanza.head, self.node_path)
                else:
                    self.logger.error(
                        "[HydraWorkerNode] failed to regrow head=%s on node=%s after health cry sad face, will try again later",
                        stanza.head, self.node_path)
        except splunk.AuthenticationFailed:
            self.logger.exception(
                "[HydraWorkerNode] could not act on the hydra health conf for node=%s, due to auth failure, refreshing session_key...",
                self.node_path)
            self.updateStatus(refresh_session_key=True)
        except Exception as e:
            self.logger.exception("[HydraWorkerNode] could not act on the hydra health conf for node=%s, message: %s",
                                  self.node_path, str(e))

        #Finally log what we did
        if bounced_heads == 0:
            self.logger.debug("[HydraWorkerNode] no heads regrown after they cried for help on node=%s", self.node_path)
        else:
            self.logger.info("[HydraWorkerNode] head_count=%s regrown after crying for help on node=%s", bounced_heads,
                             self.node_path)

    def addJob(self, priority_job_tuple, config_token=None, is_atomic=False):
        """
        Add a new job to the open queue

        @type priority_job_tuple: tuple
        @param priority_job_tuple: tuple of (priority num, JobTuple)
        @type config_token: HydraConfigToken
        @param config_token: the HydraConfigToken that created the job
        @type is_atomic: bool
        @param is_atomic: True if the job to be assigned is atomic, False otherwise

        @rtype: bool
        @return: status boolean
        """
        self.add_jobs.append(priority_job_tuple)
        if is_atomic:
            priority_num, job_tuple = priority_job_tuple
            del priority_num
            self.atomic_add_jobs[job_tuple.name] = config_token

        return True

    def commitJobs(self):
        """
        Take all jobs in the add_jobs queue and commit them to the gateway on
        this data collection node. If tyhere is a communication failure return

        @rtype: tuple
        @return: (any jobs that need to be reassigned as a list, atomic job names to config tokens as dict)
        """
        to_reassign = []
        atomic_to_reassign = {}
        #Send to the worker
        #TODO: we still want to look at handling partial job parse completes both in the gateway service and here (implement a status code 205)
        if len(self.add_jobs) > 0:
            status_code = self.gateway_adapter.commit_job_batch(self.add_jobs)
            if status_code == 200:
                self.logger.debug("[HydraWorkerNode] successfully saved job batch on node=%s with number_new_jobs=%s",
                                  self.node_path, len(self.add_jobs))
                for job_name, config_token in self.atomic_add_jobs.iteritems():
                    config_token.register_assignment(job_name, self.node_path)
            else:
                self.logger.error(
                    "[HydraWorkerNode] could not save job batch on node=%s got a status_code=%s may be a sad face situation for that node",
                    self.node_path, status_code)
                self.updateStatus(refresh_session_key=True)
                to_reassign = self.add_jobs
                atomic_to_reassign = self.atomic_add_jobs

        #Finally we added all our jobs so we set the add jobs to empty
        self.add_jobs = []
        self.atomic_add_jobs = {}

        return to_reassign, atomic_to_reassign

    def setMetadata(self, metadata_dict, bounce_heads=True):
        """
        Set the metadata stanza on this node to reflect the given dict.
        If it fails this node is marked as dead

        RETURNS nothing
        """
        #build new metadata stanza
        success = False
        try:
            new_metadata_stanza = HydraMetadataStanza(self.app, "nobody", "metadata", host_path=self.node_path,
                                                      sessionKey=self.session_key)
            for metadata_id, metadata in metadata_dict.iteritems():
                setattr(new_metadata_stanza, metadata_id, metadata)

            old_metadata_stanza = HydraMetadataStanza.from_name("metadata", self.app, "nobody", self.node_path,
                                                                self.session_key)
            if old_metadata_stanza:
                if not old_metadata_stanza.passive_delete():
                    self.logger.error(
                        "[HydraWorkerNode] node=%s failed to delete old metadata, some unnecessary data may linger",
                        self.node_path)
            if not new_metadata_stanza.passive_save():
                self.logger.error(
                    "[HydraWorkerNode] node=%s failed to save new metadata, node is effectively dead, will attempt to resurrect...",
                    self.node_path)
                self.status = HydraWorkerNode.OFFLINE
            else:
                if bounce_heads and hasattr(self, "heads_list"):
                    #Since metadata was updated we bounce the heads on the remote node to get them to pick up the new metadata
                    heads = self.heads_list
                    self.disableHeads(heads)
                    self.enableHeads(heads)
            success = True
            self.logger.info("[HydraWorkerNode] New meta data is distributed: %s.", new_metadata_stanza)
        except splunk.SplunkdConnectionException:
            self.logger.error(
                "[HydraWorkerNode] node=%s is dead, could not connect to splunkd check path and if splunkd is up on remote node",
                self.node_path)
        except splunk.LicenseRestriction:
            self.logger.error("[HydraWorkerNode] node=%s is dead due to a license issue", self.node_path)
        except splunk.AuthorizationFailed:
            self.logger.error(
                "[HydraWorkerNode] node=%s is dead, could connect to splunkd but failed to auth check username and password",
                self.node_path)
        except Exception as e:
            self.logger.exception("[HydraWorkerNode] node=%s is dead, because some weird stuff happened: %s",
                                  self.node_path, str(e))
        if not success:
            self.status = HydraWorkerNode.OFFLINE


class HydraWorkerNodeManifest(object):
    """
    This is a container for many HydraWorkerNode objects.
    It provides convenience methods for dealing with groups of nodes.
    """

    def __init__(self, logger, node_list, app, worker_input_name):
        """
        Construct a manifest with the given nodes.
        args:
            logger - a logger instance
            node_list - a list of HydraWorkerNode Objects
            app - the app namespace to apply to the nodes
        """
        self.logger = logger
        self.worker_input_name = worker_input_name
        self.nodes = node_list
        node_path_list = []
        nodes_by_path = {}
        for node in node_list:
            node_path_list.append(node.node_path)
            nodes_by_path[node.node_path] = node
        self.all_node_paths = node_path_list
        self.nodes_by_path = nodes_by_path
        self.app = app
        self.active_nodes, self.dead_nodes = self.getNodes()
        self.target_node_affinity = {}

    def updateTargetNodeAffinity(self, target, node_path):
        """
        Update the target node affinity object to reflect the assignment of one
        of a target to a particular node.
        args:
            target - the target whose affinities need to be updated
            node_path - the path of the node that just did business with the target

        RETURNS nothing
        """
        node_affinity_array = self.target_node_affinity.get(target, False)
        if not node_affinity_array:
            node_affinity_array = []
            self.target_node_affinity[target] = node_affinity_array
        try:
            node_affinity_array.remove(node_path)
        except ValueError:
            self.logger.info(
                "[HydraWorkerNodeManifest] first time job for target={0} assigned to worker={1}".format(target,
                                                                                                        node_path))
        #Update by reference
        node_affinity_array.insert(0, node_path)

    def getPreferredNodesForTarget(self, target):
        """
        Get the node affinity for a particular target
        args:
            target - the target for which you want the node affinity

        RETURNS an array of node_paths ordered from preferred to least preferred
        """
        return self.target_node_affinity.get(target, False) or []

    def refreshNodes(self, confirm_status=True):
        """
        Refresh the active and dead nodes lists
        """
        self.active_nodes, self.dead_nodes = self.getNodes(confirm_status=confirm_status)

    def getNodes(self, confirm_status=False):
        """
        This method retrieves a list of active nodes, that is nodes that
        have a status value of HydraWorkerNode.ONLINE. The nodes are not
        tested for whether or not they are online unless conirm_status is
        True. If confirm_status is True nodes will also attempt to refresh
        their session_keys if they are failing.
        args:
            confirm_status - flag indicating whether or not to test the
                             status of the nodes

        RETURNS a list of online HydraWorkerNode objects and a list of offline
        """
        active_nodes = []
        dead_nodes = []
        self.logger.debug("[HydraWorkerNodeManifest] checking the status of all nodes")
        if confirm_status:
            for node in self.nodes:
                if node.updateStatus(refresh_session_key=True):
                    active_nodes.append(node)
                else:
                    dead_nodes.append(node)
        else:
            for node in self.nodes:
                if node.status == HydraWorkerNode.ONLINE:
                    active_nodes.append(node)
                else:
                    dead_nodes.append(node)

        return active_nodes, dead_nodes

    def checkHealth(self, active_nodes=None):
        """
        Check the health of nodes, bouncing any heads that have not reported in.

        RETURNS: nothing
        """
        if active_nodes is None:
            active_nodes = self.active_nodes
        for node in active_nodes:
            self.logger.debug("[HydraWorkerNodeManifest] checking health of node=%s", node.node_path)
            node.checkHeadHealth()

    def resurrectDeadNodes(self):
        """
        Work through the dead nodes trying to bring them back to life

        RETURNS a list of nodes that were brought back to life
        """
        resurrected_nodes = []
        for ii in range(len(self.dead_nodes)):
            node = self.dead_nodes[ii]
            self.logger.debug("[HydraWorkerNodeManifest] attempting to resurrect node=%s", str(node))
            if node.resurrect():
                self.logger.debug("[HydraWorkerNodeManifest] successfully resurrected node=%s", str(node))
                resurrected_nodes.append(node)
                self.dead_nodes.pop(ii)
            else:
                self.logger.info("[HydraWorkerNodeManifest] failed to resurrect node=%s", str(node))
        if len(resurrected_nodes) > 0:
            self.active_nodes += resurrected_nodes

        return resurrected_nodes

    def sprayJobSet(self, job_set, atomic_job_set):
        """
        This is a safety method in case something happens during ready job assignment.
        It is non ideal and just dumps jobs out to workers as quick as possible

        @type job_set: list
        @param job_set: this is an iterable of JobTuple
        @type atomic_job_set: dict
        @param atomic_job_set: dict of job_name -> config_token that created it

        @rtype: None
        @return None
        """
        self.logger.debug("[HydraWorkerNodeManifest] failover to generic job spray initiated")
        self.refreshNodes(confirm_status=False)
        worker_count = len(self.active_nodes)
        if worker_count < 1:
            self.logger.error(
                "[HydraWorkerNodeManifest] Attempted to assign jobs but we have no active workers to assign to. Restarting Scheduler...")
            raise ForceHydraRebuild
        worker_index = 0
        for job_tuple in job_set:
            if isinstance(job_tuple, JobTuple):
                job_name = job_tuple.name
                task = job_tuple.task
            elif isinstance(job_tuple, tuple) and len(job_tuple) == 2:
                job_name = job_tuple[1].name
                task = job_tuple[1].task
            else:
                raise TypeError(
                    "Unexpected type=%s and size inside job_batch, expected either JobTuple or tuple of form (priority, JobTuple)" % type(
                        job_tuple))
            iter_count = 0
            while iter_count < worker_count:
                iter_count += 1
                if worker_index == worker_count:
                    worker_index = 0
                worker = self.active_nodes[worker_index]
                worker_index += 1
                if worker.hasCapability(task):
                    if job_name in atomic_job_set:
                        worker.addJob(job_tuple, atomic_job_set[job_name], True)
                    else:
                        worker.addJob(job_tuple)
                    break
            else:
                self.logger.error(
                    "[HydraCollectionManifest] unable to find an active node capable of executing job=%s of task=%s if no node configured for this task becomes active jobs of this task will never be assigned",
                    job_tuple, task)

        #Now that we have established the assignments, we actually commit the queues
        reassign_jobs = []
        atomic_reassign_jobs = {}
        for worker in self.active_nodes:
            try:
                failed_to_assign, atomic_failed_to_assign = worker.commitJobs()
                reassign_jobs += failed_to_assign
                atomic_reassign_jobs.update(atomic_failed_to_assign)
            except Exception:
                self.logger.exception(
                    "[HydraCollectionManifest] failed to assign batch of jobs for node=%s, marking dead and reassigning jobs to others, may cause job duplication",
                    worker.node_path)
                reassign_jobs += worker.add_jobs
                worker.add_jobs = []

        if reassign_jobs != []:
            #call primitive sprayJobSet that sprays already parsed jobs.
            self.sprayJobSet(reassign_jobs, atomic_reassign_jobs)

    def commitMetadata(self, metadata_dict):
        """
        Set the metadata stanza for all active nodes to the passed dict
        Note that this deletes all past metadata which may result in the failure of
        old jobs if metadata has changed
        """
        for worker in self.active_nodes:
            worker.setMetadata(metadata_dict)
        self.refreshNodes()


class HydraScheduler(ModularInput):
    title = "Hydra Scheduler"
    description = "Schedule Distributed Work. DO NOT have more than one scheduler working simultaneously. It will result in task duplication"
    collection_model = None
    app = None
    collection_conf_name = None
    worker_input_name = None
    generate_auto_offset = True

    def __init__(self):
        self.output = XMLOutputManager()
        args = [
            Field("name", "Scheduler Name",
                  "A name for your scheduler input to attach to all events that originate from it directly.",
                  required_on_create=False),
            Field("log_level", "Logging Level", "This is the level at which the scheduler will log data.",
                  required_on_create=True),
            DurationField("duration", "Duration",
                          "This is the minimum time between runs of the input should it exit for some reason",
                          required_on_create=True)
        ]
        scheme_args = {'title': self.title,
                       'description': self.description,
                       'use_external_validation': "true",
                       'streaming_mode': "xml",
                       'use_single_instance': "false"}
        ModularInput.__init__(self, scheme_args, args)

        # Use the below data to update data in hydra_avg_execution_time.json
        self.checkpoint_file = "hydra_avg_execution_time.json"
        # Number of cycle of scheduler after that check point dir need to be updated
        # TODO: this value should be relative to interval or duration value
        self.checkpoint_update_cycle = 200

    def checkDeadNodes(self):
        """
        Check a the node manifest's dead nodes and attempt to bring them back up.
        If they come back up, give them some credentials.

        RETURNS: nothing
        """
        resurrected_nodes = self.node_manifest.resurrectDeadNodes()
        if len(resurrected_nodes) > 0:
            self.logger.info("distributing credentials and metadata to newly resurrected nodes=%s", resurrected_nodes)
            self.distributeCredentials(resurrected_nodes)
            self.distributeMetadata(resurrected_nodes)


    def augmentMetadataByStanza(self, config, stanza_name):
        """
        Overload this method to augment the metadata used by a particular job.
        Editing config by reference will edit the configuration for all jobs
        in the stanza.

        RETURNS nothing (all edits must be done by reference)
        """
        pass

    def augmentMetadataByTarget(self, special, config, stanza_name, target):
        """
        Overload this method to augment the metadata used by a particular job.
        Editing config by reference will edit the configuration for all jobs
        in the stanza.
        Editing special by reference will edit it only for particular targets
        within the stanza.

        RETURNS nothing (all edits must be done by reference)
        """
        pass

    def augmentMetadataByTask(self, special, config, stanza_name, target, task):
        """
        Overload this method to augment the metadata used by a particular job.
        Editing config by reference will edit the configuration for all jobs
        in the stanza.
        Editing special by reference will edit it only for particular target
        task pairs within the stanza.

        RETURNS nothing (all edits must be done by reference)
        """
        pass

    def augmentTaskExecutionTime(self, collection_manifest):
        '''
            Overload this methof to agument execution time for task or target|task|metadata_id
            level
            @param collection_manifest: HydraCollectionManifest object which is created earlier
            @return modifies object of collection_manifest
        '''
        # Read data from check point dir
        if self.checkpoint_data_exists(self.checkpoint_file, self.checkpoint_dir):
            data = self.get_checkpoint_data(self.checkpoint_file, self.checkpoint_dir)
            # Update data at task level target_task_metadata_level_data, task_level_data
            if data and isinstance(data, dict):
                for key, items in data.get("task_level_data", {}).iteritems():
                    # Reset the count
                    items[1] = 1
                    if collection_manifest.task_aggre_exec_time.has_key(key):
                        collection_manifest.task_aggre_exec_time[key] = tuple(items)
                for key, items in data.get("target_task_metadata_level_data", {}).iteritems():
                    # Reset the count
                    items[1] = 1
                    # if target is deleted then we do not want to read information about that target
                    if collection_manifest.task_target_metaid_aggre_exec_time.has_key(key):
                        collection_manifest.task_target_metaid_aggre_exec_time[key] = tuple(items)
        return collection_manifest

    def getConfigTokenOffsets(self, token_list, total_worker_heads, schedular_execution_time=15,
                              head_dist_bucketsize=2):
        """
            Calculate offset values for job if no of jobs are more than is head_dist_bucketsize*total_worker_heads
            Offset values is being calculated by grouping equal interval together and assign offset value for those
            interval

            @param:
                token_list - HydraConfigToken list
                total_worker_heads - total active heads
                schedular_execution_time - schedular execution time
                head_dist_bucketsize - Min bucket counts for each head job buckets

            @return: dict of offset for each job
        """
        self.logger.info("Start process to get initial offset for number of jobs %s", len(token_list))
        # Note minimum jobs assign to each worker is 2 (head_distribution_size), so it token is more than 2* total_heads
        if (head_dist_bucketsize * total_worker_heads > len(token_list)):
            self.logger.info(
                "Total jobs are less than threashold value of worker(s) load, hence no need to set auto job offset")
            return
        # check for schedular execution time
        if schedular_execution_time == 0:
            self.logger.info("Schedular execution time can't be zero, returning default offset values")
            return

        # Group equal interval token for per target
        group_dict = {}
        for token in token_list:
            if group_dict.get(token.interval, False):
                # Interval already exists, add token to existing list
                self.logger.debug("Appending token %s in interval %s", token, token.interval)
                group_dict[token.interval].append(token)
            else:
                # Add _internval first time
                self.logger.info("Adding first time data %s interval %s", token, token.interval)
                group_dict[token.interval] = [token]
        # Done with grouping, now apply algorithm for each group of token
        self.logger.debug("Calculated group based upon interval %s", str(group_dict))

        for interval, tokens in group_dict.iteritems():
            if len(tokens) <= 1:
                # Only one job, no need to distribute
                self.logger.debug(
                    "Auto offset algorithm work only if there is more than one job has same interval. We found only one job with interval value=%s, hence skipping auto offset calcualtion for it",
                    interval)
                continue
            if interval is None or interval <= schedular_execution_time:
                # Make sure we have atleast one cycle to set auto set
                temp_interval = schedular_execution_time
                self.logger.debug(
                    "To calculate offset, job interval should be more than hydra schedular execution time, hence distribute offset with in interval (hydra schedular time)=%s",
                    temp_interval)
            else:
                temp_interval = interval
            # No of schedular cycle to distribute jobs over the cycles
            no_of_cycles = math.ceil(float(interval) / schedular_execution_time)
            self.logger.debug(
                "Number of hydra schedular cycles=%s, in which job is distributed by adding offset value.",
                no_of_cycles)
            # Load balance factor which allow to jobs offset by no of jobs in that interval
            # For example 10 cycles, 3 tokens, allow to set offset of interval of 45
            increasing_offset_factor = math.floor(no_of_cycles / len(tokens)) * schedular_execution_time
            # if Jobs (token) are more than no of cycles
            if increasing_offset_factor == 0:
                increasing_offset_factor = schedular_execution_time

            self.logger.debug("Job offset incremental value=%s", increasing_offset_factor)
            for ii in range(len(tokens)):
                if tokens[ii].task + "_offset" in tokens[ii].metadata:
                    self.logger.info("External offset is set hence ignoring the auto offset")
                else:
                    tokens[ii].setOffset((ii % no_of_cycles) * increasing_offset_factor)
                    self.logger.info("New initial offset %s for token %s",
                                     (ii % no_of_cycles) * increasing_offset_factor, tokens[ii])
        self.logger.info("Successfully set offsets for all tokens")

    def updateCheckPointDir(self, collection_manifest):
        '''
            Update check point dir using collection_manifest object
        '''
        if collection_manifest:
            self.set_checkpoint_data(self.checkpoint_file,
                                     {"task_level_data": collection_manifest.task_aggre_exec_time,
                                      "target_task_metadata_level_data": collection_manifest.task_target_metaid_aggre_exec_time},
                                     self.checkpoint_dir)
            self.logger.info("Updated check point file=%s successfully", self.checkpoint_file)
        else:
            self.logger.error("Failed to update check point file=%s, because collection manifest is not defined.",
                              self.checkpoint_file)

    def establishCollectionManifest(self, calculate_auto_offset=False, total_heads=0):
        """
        Get the information from the collection conf then break it up into
        atomic tasks and place them in the collection manifest

        @param:
          calculate_auto_offset: Required if initial offset needs to be calculated
          total_heads: total active worker heads, required if calculate_auto_offset is set to True

        return HydraCollectionManifest with entire contents of collect conf file
        """
        #Get collection conf information
        for retry in range(4):
            collects = self.collection_model.all(host_path=self.local_server_uri, sessionKey=self.local_session_key)
            collects._owner = "nobody"
            collects = collects.filter_by_app(self.app)
            if collects is not None and len(collects) > 0:
                break
            else:
                if retry == 3:
                    self.logger.error(
                        "[establishCollectionManifest] Could not get collection or no collection defined from scheduler host=%s, after number of retry=%s",
                        self.local_server_uri, retry)
                    raise ForceHydraRebuild(
                        "[establishCollectionManifest] Failed to get collection, hence rebuilding hydra...")
                else:
                    self.logger.error(
                        "[establishCollectionManifest] Could not get collection or no collection defined from scheduler host=%s, after number of retry=%s",
                        self.local_server_uri, retry)
        metadata_dict = {}
        token_list = []

        for collect in collects:
            self.logger.info("Processing collection stanza={0}".format(collect.name))
            config = {}
            username = collect.username
            for field in collect.model_fields:
                #forgive me this but models don't implement a get item function so we have to do this
                config[field] = getattr(collect, field)
            self.logger.info("parsed collection stanza={0} into a config={1}".format(collect.name, str(config)))
            metadata_id = "metadata_" + collect.name
            metadata_dict[metadata_id] = config
            self.augmentMetadataByStanza(config, collect.name)
            special = {}
            for target in collect.target:
                self.augmentMetadataByTarget(special, config, collect.name, collect.target)
                for task in collect.task:
                    self.augmentMetadataByTask(special, config, collect.name, collect.target, collect.task)
                    token_list.append(
                        HydraConfigToken(target, username, task, metadata_id, self.logger, metadata=config,
                                         special=special))
        self.logger.debug("Establishing collection manifest with token list: {0}".format(str(token_list)))

        # calculate auto offset
        if calculate_auto_offset:
            self.getConfigTokenOffsets(token_list, total_heads, schedular_execution_time=self.scheduling_resolution,
                                       head_dist_bucketsize=2)
        #Distribute Metadata to all nodes
        self.metadata_dict = metadata_dict

        collection_manifest = HydraCollectionManifest(self.logger, metadata_dict, token_list, self.app)
        collection_manifest = self.augmentTaskExecutionTime(collection_manifest)
        return collection_manifest

    def distributeCredentials(self, nodes):
        """
        This takes in a list of nodes and then distributes all credentials
        local to the current app to all the nodes, excluding node credentials.
        args:
            nodes - list of HydraWorkerNode objects to distribute credentials to

        RETURNS nothing
        """
        #gather up our credentials
        creds = SplunkStoredCredential.all(host_path=self.local_server_uri, sessionKey=self.local_session_key)
        creds = creds.filter_by_app(self.app)
        creds._owner = "nobody"  #FIXME: nobody no no
        node_paths = self.node_manifest.all_node_paths
        self.logger.debug("attempting to distribute local credentials to nodes={0}".format(str(nodes)))
        for cred in creds:
            self.logger.debug("processing credential for realm={0} user={1}".format(cred.realm, cred.username))
            #Do not distribute node credentials!
            if cred.realm in node_paths:
                continue
            for node in nodes:
                new_cred = SplunkStoredCredential(self.app, "nobody", cred.username, sessionKey=node.session_key,
                                                  host_path=node.node_path)
                new_cred.realm = cred.realm
                new_cred.password = cred.clear_password
                new_cred.username = cred.username
                if not new_cred.passive_save():
                    self.logger.error(
                        "Failed to distribute credential: realm={0} username={1} to node={2}".format(cred.realm,
                                                                                                     cred.username,
                                                                                                     node.node_path))
                else:
                    self.logger.debug(
                        "Successfully distributed credential: realm={0} username={1} to node={2}".format(cred.realm,
                                                                                                         cred.username,
                                                                                                         node.node_path))
        self.logger.debug("finished distributing local credentials to nodes={0}".format(str(nodes)))

    def distributeMetadata(self, node_list=None):
        """
        If we have both a metadata dict and a node manifest, distribute the metadata to all nodes
        args:
            node_list - if not None will only distribute metadata to given list of HydraWorkerNode objects

        RETURNS nothing
        """
        if node_list is not None and self.metadata_dict is not None:
            for node in node_list:
                node.setMetadata(self.metadata_dict)
            if self.node_manifest is not None:
                self.node_manifest.refreshNodes()
        elif self.node_manifest is not None and self.metadata_dict is not None:
            self.node_manifest.commitMetadata(self.metadata_dict)


    def establishNodeManifest(self):
        """
        Get all configured worker nodes and construct a node manifest

        RETURNS: HydraWorkerNodeManifest Instance will all configured nodes
        """
        #Establish node list
        node_stanzas = HydraNodeStanza.all(host_path=self.local_server_uri, sessionKey=self.local_session_key)
        node_stanzas._owner = "nobody"  #self.asset_owner
        node_stanzas = node_stanzas.filter_by_app(self.app)

        #Iterate on all nodes, checking if alive and sorting appropriately
        node_list = []
        for node_stanza in node_stanzas:
            password = SplunkStoredCredential.get_password(node_stanza.name, node_stanza.user, self.app,
                                                           session_key=self.local_session_key,
                                                           host_path=self.local_server_uri)
            if isinstance(node_stanza.gateway_port, int):
                gateway_port = node_stanza.gateway_port
            else:
                gateway_port = 8008
            gateway_uri = node_stanza.name.rstrip("/0123456789") + str(gateway_port)
            node = HydraWorkerNode(self.logger, node_stanza.name, password, node_stanza, gateway_uri,
                                   metadata_dict=self.metadata_dict, worker_input_name=self.worker_input_name)
            node_list.append(node)

        return HydraWorkerNodeManifest(self.logger, node_list, self.app, self.worker_input_name)

    def run(self, stanza):
        #Get config info
        if isinstance(stanza, list):
            self.name = stanza[0].get('name', None)
            log_level = stanza[0].get("log_level", "WARN").upper()
            is_interval_field_defined = True if stanza[0].get("interval", -1) > 0 else False
        else:
            self.name = stanza.get('name', None)
            log_level = stanza.get("log_level", "WARN").upper()
            is_interval_field_defined = True if stanza.get("interval", -1) > 0 else False

        logname = "hydra_scheduler_" + self.name.replace("://", "_") + ".log"

        input_config = self._input_config
        #Handle local authentication
        self.local_session_key = input_config.session_key
        self.local_server_uri = input_config.server_uri
        #splunk.setDefault('sessionKey', local_session_key) oh but wait this will get overridden all the f'n time so we have to explicitly pass session keys
        splunk.setDefault('user', "nobody")

        #this may be made a configuration option
        self.scheduling_resolution = 5

        #Set up logger
        if log_level not in ["DEBUG", "INFO", "WARN", "WARNING", "ERROR"]:
            log_level = logging.WARN
            self.logger = setupLogger(logger=None,
                                      log_format='%(asctime)s %(levelname)s [' + self.name + '] %(message)s',
                                      level=log_level, log_name=logname)
            self.logger.warn("log_level was set to a non-recognizable level it has be reset to WARNING level")
        else:
            self.logger = setupLogger(logger=None,
                                      log_format='%(asctime)s %(levelname)s [' + self.name + '] %(message)s',
                                      level=log_level, log_name=logname)
            self.logger.debug("logger reset with log level of {0}".format(log_level))

        #Self Validation
        if self.collection_model is None:
            self.logger.error(
                "HydraScheduler implementation {0} did not have a collection model specified, you must specify a collection model".format(
                    self.name))
            raise NotImplementedError("All HydraScheduler implementations must specify a collection model.")
        if self.app is None:
            self.logger.error(
                "HydraScheduler implementation {0} did not have an app specified, you must specify an app".format(
                    self.name))
            raise NotImplementedError("All HydraScheduler implementations must specify an app.")
        if self.collection_conf_name is None:
            self.logger.error(
                "HydraScheduler implementation {0} did not have a collection conf name specified, you must specify a collection conf or changes cannot be identified".format(
                    self.name))
            raise NotImplementedError("All HydraScheduler implementations must specify a collection conf.")
        if self.worker_input_name is None:
            self.logger.error(
                "HydraScheduler implementation {0} did not have a worker input name specified, you must specify the associated hydra worker's modular input name".format(
                    self.name))
            raise NotImplementedError(
                "All HydraScheduler implementations must specify the associated hydra worker's modular input name.")

        #Debug logging
        self.logger.debug("Initialized with local server uri of {0}".format(self.local_server_uri))

        try:
            self.metadata_dict = None
            self.node_manifest = None
            self.app_home = os.path.join(make_splunkhome_path(['etc', 'apps']), self.app)

            #Initialize node manifest
            self.node_manifest = self.establishNodeManifest()
            node_conf_mtime = HydraCommon.getConfModTime(self.app_home, "node")
            self.logger.debug("Initialized node manifest with nodes={0}".format(str(self.node_manifest.all_node_paths)))

            # Calculating number of heads to get auto initial offset.
            head_count = 0
            for worker in self.node_manifest.active_nodes:
                head_count += worker.model.heads

            #Initialize collection manifest
            collection_manifest = self.establishCollectionManifest(calculate_auto_offset=self.generate_auto_offset,
                                                                   total_heads=head_count)
            collection_conf_mtime = HydraCommon.getConfModTime(self.app_home, "collection", self.collection_conf_name)
            self.logger.debug("Initialized collection manifest")

            #Distribute packages
            self.distributeCredentials(self.node_manifest.active_nodes)
            self.distributeMetadata()

            #Loop time!
            self.output.initStream()
            while True:
                #Check if conf files have been modified
                if collection_conf_mtime < HydraCommon.getConfModTime(self.app_home, "collection",
                                                                      self.collection_conf_name):
                    collection_conf_mtime = HydraCommon.getConfModTime(self.app_home, "collection",
                                                                       self.collection_conf_name)
                    self.updateCheckPointDir(collection_manifest)
                    collection_manifest = self.establishCollectionManifest(
                        calculate_auto_offset=self.generate_auto_offset, total_heads=head_count)
                    self.distributeMetadata()
                    self.logger.debug("Re-established collection manifest after filesystem change")
                #TODO: handle continuous mode jobs here, as well as potential cancels
                if node_conf_mtime < HydraCommon.getConfModTime(self.app_home, "node"):
                    node_conf_mtime = HydraCommon.getConfModTime(self.app_home, "node")
                    self.node_manifest = self.establishNodeManifest()
                    self.distributeMetadata()
                    self.logger.info("Re-established node manifest after filesystem change")
                time_to_next_job = collection_manifest.getTimeToNextJob()
                if time_to_next_job > 0:
                    self.logger.debug("No jobs ready for scheduling going to sleep for maximum %s",
                                      self.scheduling_resolution)
                    time.sleep(min(time_to_next_job, self.scheduling_resolution))
                    continue

                #Update nodes
                ## TODO: Remove health check once we completely move to splunk 6.0 version onwards
                self.node_manifest.checkHealth()
                self.logger.debug("Updated status of active nodes")

                #Check on nodes that are inactive
                self.checkDeadNodes()
                self.logger.debug("Checked status of dead nodes")

                #Spread work around
                collection_manifest.sprayReadyJobs(self.node_manifest)
                self.logger.debug("Sprayed all ready jobs onto active nodes")

                #rinse, repeat! also maybe we should be printing some performance stats or something here?
                # update checkpoint dir
                if self.checkpoint_update_cycle <= 0:
                    self.updateCheckPointDir(collection_manifest)
                    self.checkpoint_update_cycle = 50
                else:
                    self.checkpoint_update_cycle = self.checkpoint_update_cycle - 1

            self.output.finishStream()
        except Exception, e:
            self.output.finishStream()
            self.logger.exception("Problem with hydra scheduler {0}:\n {1}".format(self.name, str(e)))
            self.logger.warning(
                "Exiting current run of hydra scheduler, expecting to restart based on duration or interval")
            # If node manifest is not establised because of any exception then UnboundLocalError error shows up
            # To avoid this we are using try ..except block to update checkPoint dir
            try:
                self.updateCheckPointDir(collection_manifest)
            except UnboundLocalError as e:
                self.logger.error("Could not save checkpoint information due to failure to establish node manifest.")

        finally:
            if not is_interval_field_defined or ver.__version__ < '6.0':
                return False
            else:
                sys.exit(1)

