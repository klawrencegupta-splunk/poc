# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
#Core Python Imports
import sys
import os
import time
import logging
import datetime
import urllib2

#Splunk Imports
import splunk
import splunk.version as ver
import hydra
from hydra_common import HydraCommon, HydraGatewayAdapter
from models import HydraMetadataStanza, HydraSessionStanza, SplunkStoredCredential, HydraGatewayStanza

#Modify Path to include SA-VMNetAppUtils/bin
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-VMNetAppUtils', 'lib']))
from SolnCommon.modinput import ModularInput, Field, ListField, DurationField


class HydraWorker(ModularInput):
    title = "Hydra Worker"
    description = "Perform Distributed Work"
    handlers = None
    app = None

    def __init__(self):
        self.output = hydra.XMLOutputManager()
        args = [
            Field("name", "Worker Name", "A name for your worker input to attach to all events that originate with it.",
                  required_on_create=False),
            ListField("capabilities", "Worker Capabilities",
                      "A comma delimited list of job types that this worker can perform.", required_on_create=False),
            Field("log_level", "Logging Level", "This is the level at which the worker will log data.",
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
        self.metadata_conf_mtime = None
        self.active_handlers = {}

    def establishMetadata(self):
        """
        Read the local metadata stanza and set it to self.metadata

        RETURNS nothing
        """
        while True:
            metadata_stanza = HydraMetadataStanza.from_name("metadata", self.app, "nobody")
            if metadata_stanza:
                self.metadata = metadata_stanza.parsed_wildcard_fields["metadata"]
                self.logger.info("successfully loaded metadata stanza with metadata fields=%s", self.metadata.keys())
                break
            else:
                self.logger.warning("could not find metadata stanza going to sleep for 10 seconds and retrying...")
                time.sleep(10)

    def _getMetadataForJob(self, job):
        """
        Lookup the metadata for the given job
        args:
            job - JobTuple of the job whose metadata is desired

        RETURNS a metadata dict
        """
        return self.metadata.get(job.metadata_id, None)

    def isJobExpired(self, job_id, job_tuple, metadata):
        """
        Determine if a job is expired given a particular set of metadata
        args:
            job_id - the id of the job
            job_tuple - the JobTuple namedtuple for the job
            metadata - the metadata dictionary associated with this job

        RETURNS True if expired False otherwise
        """
        expiration_period = int(job_tuple.expiration_period)
        cur_time = datetime.datetime.utcnow()
        expiration_time = job_tuple.create_time + datetime.timedelta(seconds=expiration_period)
        if expiration_time < cur_time:
            self.logger.debug("[isJobExpired] expired job=%s create_time=%s expiration_period=%s cur_time=%s task=%s target=%s",
                              job_id, job_tuple.create_time, job_tuple.expiration_period, cur_time, job_tuple.task, job_tuple.target)
        return expiration_time < cur_time

    def getJob(self):
        """
        Check for performable jobs via the hydra gateway, if none found sleep until one is available.

        RETURNS: a tuple of the job_id, named JobTuple, and the associated metadata
        """
        active_job = None
        job_id = None
        job_tuple = None
        while True:
            try:
                job_tuple = self.gateway_adapter.get_next_job()
            except urllib2.HTTPError as e:
                if e.code == 401:
                    self.logger.error("[getJob] hydra gateway adapter failed to authenticate, re-establishing...")
                    self.establishGateway()
                else:
                    self.logger.exception(
                        "[getjob] unhandled HTTP error of code=%s, sleeping before retry, exception=%s", e.code, str(e))
                    time.sleep(2)
                continue
            if job_tuple is None:
                self.logger.info("[getJob] could not find a job to do, sleeping before retry")
                time.sleep(2)
                continue
            job_id = job_tuple.name
            metadata = self._getMetadataForJob(job_tuple)
            if metadata is None:
                self.logger.error(
                    "[getJob] could not find metadata information for job=%s and it will not be run, likely due to a removal of target=%s from collection configuration",
                    job_id, job_tuple.target)
                continue
            if self.isJobExpired(job_id, job_tuple, metadata):
                self.logger.error("[getJob] job=%s of task=%s for target=%s has expired and will not be run", job_id, job_tuple.task, job_tuple.target)
                is_atomic = False
                if job_tuple.task in metadata.get("atomic_tasks", []):
                    is_atomic = True
                elif (type(job_tuple.special) == dict and len(
                        job_tuple.special) > 0) and job_tuple.task in job_tuple.special.get("atomic_tasks", []):
                    is_atomic = True
                if is_atomic:
                    self.logger.error("[getJob] reporting expired atomic job as a job failure for job=%s of task=%s for target=%s",
                                      job_id, job_tuple.task, job_tuple.target)
                    self.report_failed_atomic_job(job_tuple)
                continue

            #Looks like we found a job to do
            active_job = (job_id, job_tuple, metadata)
            break

        self.logger.debug("[getJob] found job to do, active job=%s", job_id)
        return active_job

    def report_failed_atomic_job(self, job_tuple):
        """
        Report a failed atomic job to the gateway.

        @type job_tuple: JobTuple
        @param job_tuple: the JobTuple object for the failed job

        @rtype: None
        @return None
        """
        try:

            self.gateway_adapter.report_failed_atomic_job(job_tuple)
            self.logger.info(
                "[ReportFailedAtomicJob] Successfully reported failed job to gateway for target=%s, task=%s, metadata_id=%s",
                job_tuple.target, job_tuple.task, job_tuple.metadata_id)
        except urllib2.HTTPError as e:
            if e.code == 401:
                self.logger.error(
                    "[ReportFailedAtomicJob] hydra gateway adapter failed to authenticate, re-establishing...")
                self.establishGateway()
            else:
                self.logger.exception(
                    "[ReportFailedAtomicJob] unhandled HTTP error of code=%s, skipping the update, exception=%s",
                    e.code, str(e))

    def update_job_execution_info(self, time_spent, job_tuple, is_atomic):
        '''
        Update job execution info in gateway including the execution time
        and the job_id if it was atomic.

        @type time_spent: int
        @param time_spent: total time is taken by job
        @type job_tuple: JobTuple
        @param job_tuple: the JobTuple object for the completed job
        @type is_atomic: bool
        @param is_atomic: True if the job's task was atomic, False otherwise

        @rtype: None
        @return None
        '''
        try:

            self.gateway_adapter.commit_job_exec_info(time_spent, job_tuple, is_atomic)
            self.logger.info(
                "[UpdateJobTime] Successfully reported time to gateway for target=%s, task=%s, metadata_id=%s, time=%s",
                job_tuple.target, job_tuple.task, job_tuple.metadata_id, time_spent)
        except urllib2.HTTPError as e:
            if e.code == 401:
                self.logger.error("[UpdateJobTime] hydra gateway adapter failed to authenticate, re-establishing...")
                self.establishGateway()
            else:
                self.logger.exception(
                    "[UpdateJobTime] unhandled HTTP error of code=%s, skipping the update, exception=%s", e.code,
                    str(e))

    def initializeHandlers(self):
        """
        Instantiate instances of all handlers specified in the handlers dict
        that correspond to specified capabilities of this worker process
        and store them in the active_handlers property

        RETURNS nothing
        """
        if (self.handlers is None) or (type(self.handlers) is not dict):
            self.logger.error("Problem with the handlers property, right now it is of type {0} and value {1}".format(
                str(type(self.handlers)), str(self.handlers)))
            raise NotImplementedError(
                "HydraWorker processes MUST have a handlers property consisting of a dict of task to handler classes")
        #Iterate on all handlers, instantiate them
        tmp_capabilities = self.worker_capabilities[:]
        self.active_handlers = {}
        for handled_task, task_handler in self.handlers.items():
            if "*" not in self.worker_capabilities and handled_task not in self.worker_capabilities:
                self.logger.info(
                    "Worker has handler for task outside capabilities, will not instantiate handler for task={0}".format(
                        handled_task))
            else:
                self.active_handlers[handled_task] = task_handler(self.output, self.logger, self.worker_name, self.app,
                                                                  self.gateway_adapter)
                try:
                    tmp_capabilities.remove(handled_task)
                except ValueError:
                    #If they put in a * this is benign
                    pass
                self.logger.info("Worker instantiated handler for task={0}".format(handled_task))
        if "*" in tmp_capabilities:
            tmp_capabilities.remove("*")
        if len(tmp_capabilities) > 0:
            self.logger.error(
                "worker failed to supply handler for the following tasks: {0}, any attempt to execute these tasks will fail.".format(
                    str(tmp_capabilities)))

    def loginToTarget(self, target, user, password, realm):
        """
        This method must be overloaded by any implementation of the hydra worker.
        It shall use its args to somehow create a session object passed to any handler
        performing a job associated with the particular target
        args:
            target - the uri to the domain specific asset we need to log in to
            user - the user name stored in splunkd associated with that target
            password - the password stored in splunkd associated with that target
            realm - the realm if in realm mode, else None

        RETURNS the session object for this implementation
        """
        raise NotImplementedError(
            "All HydraWorker implementations must overload loginToTarget with the valid domain specific login logic.")

    def isSessionValid(self, session):
        """
        This method must be overloaded by any implementation of the hydraworker.
        It takes in a session object returned by loginToTarget and indicates if that
        session is still valid for use by a handler.
        args:
            session - the python object returned by loginToTarget to be tested

        RETURNS True if session is valid, False if it must be refreshed
        """
        raise NotImplementedError(
            "All HydraWorker implementations must overload isSessionValid with the domain specific logic for checking session state.")


    def getPassword(self, realm, user):
        """
        This method pulls the clear password from storage/passwords for a
        particular realm and user. This wraps the util method for logging purposes.
        args:
            realm - the realm associated with the stored credential
            user - the user name associated with the stored credential

        RETURNS the clear string of the password, None if not found
        """
        #note we are relying on splunk's internal automagical session_key storage
        password = SplunkStoredCredential.get_password(realm, user, app=self.app)
        if password is None:
            self.logger.warning(
                "Could not find a stored credential for realm={0} and user={1}, sending None to loginToTarget".format(
                    realm, user))
            return None
        else:
            return password

    def acquireStanzaLock(self, stanza, lock_wait=0.1, lock_timeout=10):
        """
        Lock a conf stanza with your worker's name.
        Note that this method should only be used locally.
        args:
            stanza - the SOLNAppObjModel based model instance for the desired stanza with a worker field

        RETURNS True if able to lock and currently locked, False otherwise
        """
        return hydra.acquireStanzaLock(stanza, self.worker_name, self.logger, lock_wait, lock_timeout)

    def releaseStanzaLock(self, stanza):
        """
        Unlock a conf stanza currently locked with your worker's name.
        Note that this method should only be used locally.
        args:
            stanza - the SOLNAppObjModel based model instance for the desired stanza with a worker field

        RETURNS True if able to unlock or currently unlocked, False if under someone else's claim
        """
        return hydra.releaseStanzaLock(stanza, self.worker_name, self.logger)

    def updateSessionStanza(self, session_stanza, target, username, realm):
        """
        Acquire a lock on the session stanza and update it with username and password if it has an invalid session key upon lock
        """
        RETRY_LIMIT = 5
        retry_count = 0
        cred_realm = target if not realm else realm
        while True:
            session_stanza = session_stanza.from_self()
            if not session_stanza:
                self.logger.warning(
                    "[getSessionForTarget] problem getting session stanza for target=%s and username=%s and realm=%s, retrying...",
                    target, username, realm)
                retry_count += 1
                if retry_count > RETRY_LIMIT:
                    raise hydra.ForceHydraRebuild(
                        "[getSessionForTarget] problem getting session stanzas in hydra_stanza.conf for target={0} and username={1} and realm={2}".format(
                            target, username, realm))
                else:
                    time.sleep(15)
                    continue
            if self.isSessionValid(session_stanza.session):
                self.logger.debug(
                    "[getSessionForTarget] found valid session=%s for target=%s and username=%s and realm=%s",
                    session_stanza.session, target, username, realm)
                break
            else:
                self.logger.warning(
                    "[getSessionForTarget] could neither claim the session stanza nor use the existing session, re-trying to lock for target={0} with username={1}".format(
                        target, username))
            if self.acquireStanzaLock(session_stanza, lock_wait=1, lock_timeout=45):
                self.logger.debug(
                    "[getSessionForTarget] about to rebuild session=%s with password for target=%s and username=%s and realm=%s",
                    session_stanza.session, target, username, realm)
                password = self.getPassword(cred_realm, username)
                session = self.loginToTarget(target, username, password, realm)
                self.logger.debug(
                    "[getSessionForTarget] rebuilt into session=%s with password for target=%s and username=%s and realm=%s",
                    session, target, username, realm)
                session_stanza.session = session
                if not session_stanza.passive_save():
                    self.logger.error(
                        "[getSessionForTarget] unable to save session for target=%s and username=%s and realm=%s",
                        target, username, realm)
                else:
                    self.logger.debug(
                        "[getSessionForTarget] successfully saved session=%s for target=%s and username=%s and realm=%s",
                        session_stanza.session, target, username, realm)
                if not self.releaseStanzaLock(session_stanza):
                    self.logger.error(
                        "[getSessionForTarget] unable to release claim on session for target=%s and username=%s and realm=%s unless it was claimed by another worker lock will remain until expiration",
                        target, username, realm)
                self.logger.debug(
                    "[getSessionForTarget] returning session=%s with password for target=%s and username=%s and realm=%s",
                    session_stanza.session, target, username, realm)
            else:
                #Since we lost our lock we will check if the session is valid, if it is we will use it
                #We refresh the stanza here just in case in interim the session itself was refreshed at the top of the run
                self.logger.warning(
                    "[getSessionForTarget] could not claim invalid session stanza to update it, sleeping for 15sec")
                time.sleep(15)
        return session_stanza

    def getSessionForTarget(self, target, username, realm):
        """
        This method gets either a cached or a fresh session for a particular target that is
        tested to be a valid session.
        args:
            target - the target host for which to get the session
            username - the username to use for this particular target
            realm - the authentication realm if in realm mode, else None

        RETURNS a valid session object to the target
        """
        if target is None:
            self.logger.debug(
                "target passed as None to getSessionForTarget, cannot get a session for target of None, will return None.")
            return None
        if username is None:
            self.logger.debug(
                "username passed as None to getSessionForTarget, cannot get a session without a username, will return None.")
            return None
        session_stanza = HydraSessionStanza.from_name(target, app=self.app)
        if not session_stanza:
            self.logger.debug("[getSessionForTarget] No active/inactive session found for target, creating new one...")
            for attempt_number in range(4):
                session_stanza = HydraSessionStanza(self.app, "nobody", target)
                session_stanza.worker = self.head_name
                session_stanza.last_lock_time = datetime.datetime.utcnow()
                session_stanza.passive_save()
                session_stanza = HydraSessionStanza.from_name(target, app=self.app)
                if not session_stanza:
                    self.logger.error(
                        "[getSessionForTarget] Could not confirm creation of session stanza in attempt={0} even though it was just created will try again".format(
                            str(attempt_number)))
                    time.sleep(5)
                else:
                    break
            #If after four tries there's no session stanza, we failed just raise it and force a restart
            if not session_stanza:
                raise hydra.ForceHydraRebuild(
                    "[getSessionForTarget] Problem creating session stanzas in hydra_stanza.conf for target={0} and username={1}".format(
                        target, username))
            #Now that a session stanza exists we need to try and claim it, check if someone already made it valid, and maybe make it valid
            session_stanza = self.updateSessionStanza(session_stanza, target, username, realm)
        else:
            session_stanza = self.updateSessionStanza(session_stanza, target, username, realm)
        return session_stanza.session

    def assignJobToHandler(self, job):
        """
        This method assigns the given job to the appropriate handler and runs the handler
        args:
            job - the active and to be performed tuple of job_id, job_tuple, metadata

        RETURNS True if job successful, False if job failed
        """
        #Acquire Proper Handler
        job_id, job_tuple, metadata = job
        handler = self.active_handlers.get(job_tuple.task, None)
        if handler is None:
            raise NotImplementedError("No handler found for task={0}".format(job_tuple.task))

        #Establish a config that is the metadata updated with anything from the special if special is not empty
        if type(job_tuple.special) == dict and len(job_tuple.special) > 0:
            #metadata is copied to prevent corruption of the base metadata
            config = metadata.copy()
            config.update(job_tuple.special)
        else:
            #since there is no special we assume that the handler is not going to fuss with our metadata ref
            config = metadata

        #Check For Atomic Job
        is_atomic = False
        if job_tuple.task in config.get("atomic_tasks", []):
            is_atomic = True

        #Get Session For Target
        session = self.getSessionForTarget(job_tuple.target, config["username"], config["realm"])

        #Execute Job
        self.logger.info("Assigning job=%s of task=%s with config=%s to handler=%s for target=%s", job_id, job_tuple.task, config,
                         handler, job_tuple.target)
        job_start_time = time.time()
        if handler.run(session, config, job_tuple.create_time, job_tuple.last_time):
            self.logger.info("Successfully completed job={0} of task={1} for target={2}".format(job_id, job_tuple.task, job_tuple.target))
            job_end_time = time.time()
            total_time = job_end_time - job_start_time
            self.update_job_execution_info(total_time, job_tuple, is_atomic)
        else:
            if is_atomic:
                self.report_failed_atomic_job(job_tuple)
            self.logger.error('Failed to complete job="%s" of task="%s" against target="%s"', job_id, job_tuple.task,
                              job_tuple.target)
            self.logger.debug("Failed job=%s was passed a config=%s, session=%s, create_time=%s, and last_time=%s",
                              job_id, str(config), str(session), str(job_tuple.create_time), str(job_tuple.last_time))

    def establishGateway(self):
        """
        Safely establish the adapter to the hydra gateway on the node. If it
        cannot be established set it to None.
        """
        #Read configuration from splunkd:
        stanza = HydraGatewayStanza.from_name("gateway", "SA-Hydra", session_key=self.session_key)
        if not stanza or not isinstance(stanza.port, int):
            self.logger.warning(
                "[establishGateway] could not read gateway configuration from splunkd, defaulting to port 8008")
            gateway_port = 8008
        else:
            gateway_port = stanza.port
        self.gateway_uri = "https://" + splunk.getDefault("host") + ":" + str(gateway_port)

        #Authenticate with gateway
        hga = None
        for retry in range(4):
            self.logger.info("[establishGateway] attempting to connect to gateway=%s for node=%s ...", self.gateway_uri,
                             self.node_path)
            try:
                hga = HydraGatewayAdapter(self.node_path, self.session_key, self.gateway_uri)
                self.logger.info("[establishGateway] successfully connected to gateway=%s for node=%s",
                                 self.gateway_uri, self.node_path)
                self.logger.debug("[establishGateway] resetting gateway adapter for active_handlers=%s",
                                  self.active_handlers)
                for handler in self.active_handlers.values():
                    handler.gateway_adapter = hga
            except splunk.SplunkdConnectionException:
                self.logger.error(
                    "[establishGateway] could not connect to gateway=%s for node=%s due to a socket error, timeout, or other fundamental communication issue",
                    self.gateway_uri, self.node_path)
            except splunk.AuthenticationFailed:
                self.logger.error(
                    "[establishGateway] could not authenticate with gateway=%s for node=%s due to a splunkd authentication issue, this is fatal, forcing rebuild",
                    self.gateway_uri, self.node_path)
            except splunk.LicenseRestriction:
                self.logger.error(
                    "[establishGateway] could not authenticate with gateway=%s for node=%s due to a splunkd license issue, this is fatal, forcing rebuild",
                    self.gateway_uri, self.node_path)
            except splunk.AuthorizationFailed:
                self.logger.error(
                    "[establishGateway] could not authenticate with gateway=%s for node=%s due to a splunkd user permissions issue, this is fatal, forcing rebuild",
                    self.gateway_uri, self.node_path)
            except splunk.ResourceNotFound:
                self.logger.error(
                    "[establishGateway] could not authenticate with gateway=%s for node=%s due to missing hydra gatekeeper EAI endpoint, this is fatal, forcing rebuild",
                    self.gateway_uri, self.node_path)
            except splunk.InternalServerError as e:
                self.logger.error(
                    "[establishGateway] could not authenticate with gateway=%s for node=%s due to internal server error=%s",
                    self.gateway_uri, self.node_path, str(e))
            except splunk.BadRequest as e:
                self.logger.error(
                    "[establishGateway] could not authenticate with gateway=%s for node=%s due to bad request error=%s",
                    self.gateway_uri, self.node_path, str(e))
            except splunk.RESTException as e:
                self.logger.error(
                    "[establishGateway] could not authenticate with gateway=%s for node=%s due to some crazy REST error=%s",
                    self.gateway_uri, self.node_path, str(e))

            if hga is not None:
                break
            else:
                self.logger.warn("[establishGateway] failed to establish gateway on try=%s", str(retry + 1))

        if hga is not None:
            self.gateway_adapter = hga
        else:
            raise hydra.ForceHydraRebuild("Could not authenticate with local Hydra Gateway")

    def cry(self, message):
        """
        Cry out to the hydra_health conf file. When read by the scheduler
        this should result in a total refresh of this process.
        :'(

        RETURNS: nothing
        """
        f = open(make_splunkhome_path(['etc', 'apps', self.app, 'local', 'hydra_health.conf']), 'a')
        stanza = "[" + str(time.time()) + "]\nhead=" + self.head_name + "\nreason=" + str(message) + "\n"
        f.write(stanza)
        f.close()

    def run(self, stanza):
        #Handle configuration parsing and logging setup
        if isinstance(stanza, list):
            self.worker_name = stanza[0].get('name', None)
            worker_log_level = stanza[0].get("log_level", "WARN").upper()
            self.worker_capabilities = stanza[0].get("capabilities", "*")
            is_interval_field_defined = True if stanza[0].get("interval", -1) > 0 else False
        else:
            self.worker_name = stanza.get('name', None)
            worker_log_level = stanza.get("log_level", "WARN").upper()
            self.worker_capabilities = stanza.get("capabilities", "*")
            is_interval_field_defined = True if stanza.get("interval", -1) > 0 else False

        input_config = self._input_config
        self.head_name = self.worker_name.split("/", 1)[1].lstrip("/")
        logname = "hydra_worker_" + self.worker_name.replace("://", "_") + ".log"
        self.worker_name_full = self.worker_name + ":" + str(os.getpid());

        if worker_log_level not in ["DEBUG", "INFO", "WARN", "WARNING", "ERROR"]:
            worker_log_level = logging.WARN
            self.logger = hydra.setupLogger(logger=None,
                                            log_format='%(asctime)s %(levelname)s [' + self.worker_name_full + '] %(message)s',
                                            level=worker_log_level, log_name=logname)
            self.logger.warn("log_level was set to a non-recognizable level it has be reset to WARNING level")
        else:
            self.logger = hydra.setupLogger(logger=None,
                                            log_format='%(asctime)s %(levelname)s [' + self.worker_name_full + '] %(message)s',
                                            level=worker_log_level, log_name=logname)
            self.logger.debug("logger reset with log level of {0}".format(worker_log_level))

        #Handle local authentication automagically
        splunk.setDefault('sessionKey', input_config.session_key)

        try:
            #Set up gateway
            self.node_path = splunk.mergeHostPath()
            self.session_key = input_config.session_key
            self.establishGateway()

            #Set up worker handlers and capabilities
            self.logger.info(
                "Initiating worker={0} with capabilities={1} and handlers={2}".format(self.worker_name_full,
                                                                                      str(self.worker_capabilities),
                                                                                      str(self.handlers)))
            #Confirm we have been implemented correctly
            if self.app is None:
                raise NotImplementedError(
                    "All workers must implement a self.app property in order to establish namespace")
            self.app_home = os.path.join(make_splunkhome_path(['etc', 'apps']), self.app)
            self.initializeHandlers()

            self.output.initStream()
            while True:
                #Refresh the metadata on the worker if necessary
                metadata_mtime = HydraCommon.getConfModTime(self.app_home, "metadata")
                if self.metadata_conf_mtime == None or self.metadata_conf_mtime < metadata_mtime:
                    self.establishMetadata()
                    self.metadata_conf_mtime = metadata_mtime
                #Ask for our new job
                cur_job = self.getJob();
                #handle it
                self.assignJobToHandler(cur_job)
                #oh yeah we handled that
                self.logger.debug("handled job=%s of task=%s", cur_job[0], cur_job[1].task)
                #Let's try to give splunk a chance to respond to things
                time.sleep(0.1)
            self.output.finishStream()
        except splunk.AuthenticationFailed as e:
            self.output.finishStream()
            ## Old behavior is required for netapp, remove me when netapp support splunk 6.0.x version onwards
            if not is_interval_field_defined or ver.__version__ < '6.0':
                self.cry("Unrecoverable Local Authentication Failure")
            self.logger.error(
                "Crying due to unrecoverable problem with hydra worker {0}: {1}".format(self.worker_name_full, str(e)))
            self.logger.error(
                "Exiting current run of hydra worker, expecting restart by scheduler on next job assignment run")
            sys.exit(1)
        except hydra.ForceHydraRebuild as e:
            self.output.finishStream()
            ## Old behavior is required for netapp, remove me when netapp support splunk 6.0.x version onwards
            if not is_interval_field_defined or ver.__version__ < '6.0':
                self.cry("Unrecoverable Hydra Problem")
            self.logger.error(
                "Crying due to unrecoverable problem with hydra worker {0}: {1}".format(self.worker_name_full, str(e)))
            self.logger.error(
                "Exiting current run of hydra worker, expecting restart by scheduler on next job assignment run")
            sys.exit(1)
        except Exception as e:
            self.output.finishStream()
            self.logger.exception("Problem with hydra worker {0}: {1}".format(self.worker_name_full, str(e)))
            self.logger.warning(
                "Exiting current run of hydra worker, expecting to restart based on duration or interval")
            ## Old behavior is required for netapp, remove me when netapp support splunk 6.0.x version onwards
            if not is_interval_field_defined or ver.__version__ < '6.0':
                return False
            else:
                sys.exit(1)
