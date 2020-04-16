import xml.sax.saxutils
import logging
import logging.handlers
import sys
import time as time_module
import datetime

import splunk.rest as rest
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path
from models import HydraCacheStanza, SOLNAppObjModel

########################################################################
# EXCEPTIONS
########################################################################
class ForceHydraRebuild(Exception):
	def __init__(self, message="Something went unstable with a Hydra asset, typically due to a REST timeout or misconfiguration, rebuilding and validating entities"):
		Exception.__init__(self, message)

########################################################################
# UTILITIES
########################################################################
def setupLogger(logger=None, log_format='%(asctime)s %(levelname)s [Hydra] %(message)s', level=logging.DEBUG, log_name="hydra.log", logger_name="hydra"):
	"""
	Setup a logger suitable for splunkd consumption
	"""
	if logger is None:
		logger = logging.getLogger(logger_name)

	logger.propagate = False # Prevent the log messages from being duplicated in the python.log file
	logger.setLevel(level)

	file_handler = logging.handlers.RotatingFileHandler(make_splunkhome_path(['var', 'log', 'splunk', log_name]), maxBytes=2500000, backupCount=5)
	formatter = logging.Formatter(log_format)
	file_handler.setFormatter(formatter)

	logger.handlers = []
	logger.addHandler(file_handler)

	logger.debug("Init hydra logger")

	return logger

def acquireStanzaLock(stanza, worker, logger, lock_wait=0.1, lock_timeout=10):
		"""
		Lock a conf stanza with a worker's name.
		Note that this method should only be used locally.
		args:
			stanza - the SOLNAppObjModel based model instance for the desired stanza with a worker field
			worker - the full name for the worker locking the stanza
			logger - a logger instance
			lock_wait - the time to wait before confirming claim
			lock_timeout - the timeout period for unreleased locks

		RETURNS True if able to lock and currently locked, False otherwise
		"""
		if not isinstance(stanza, SOLNAppObjModel):
			raise TypeError("Attempted to lock a stanza that was not a SOLNAppObjModel stanza={0}".format(str(stanza)))
		if not "worker" in stanza.model_fields:
			raise TypeError("Attempted to lock a stanza that didn't have a worker field stanza={0}".format(str(stanza)))
		if not "last_lock_time" in stanza.model_fields:
			raise TypeError("Attempted to lock a stanza that didn't have a last_lock_time field stanza={0}".format(str(stanza)))
		if stanza.worker == worker:
			#refresh the lock time
			stanza.last_lock_time = datetime.datetime.utcnow()
			logger.debug("[HydraStanzaLocker] stanza={0} with stanza_name={1} already claimed/locked by this worker={2}, no work necessary".format(str(stanza), stanza.name, stanza.worker))
			return True
		#Deal with the lock time
		time_lock_gate = False
		if stanza.last_lock_time is None:
			#This stanza has never been locked before thus we can lock it
			time_lock_gate = True
		else:
			#Check if the lock is expired, by default 10s
			time_lock_gate = (datetime.datetime.utcnow() - stanza.last_lock_time) > datetime.timedelta(seconds=lock_timeout)
		if stanza.worker != "unassigned" and not time_lock_gate:
			logger.debug("[HydraStanzaLocker] cannot claim/lock stanza={0} with stanza_name={1} due to existing claim from worker={2}".format(str(stanza), stanza.name, stanza.worker))
			return False
		elif time_lock_gate and stanza.worker != "unassigned":
			logger.debug("[HydraStanzaLocker] lock from worker=%s for stanza=%s is expired, reclaiming", stanza.worker, str(stanza))

		#note that this sets the worker field in the stanza to the passed worker by reference
		stanza.worker = worker
		stanza.last_lock_time = datetime.datetime.utcnow()
		logger.debug("[HydraStanzaLocker] attempting to claim/lock stanza_name=%s", stanza.name)
		if not stanza.passive_save():
			logger.error("[HydraStanzaLocker] Failed to save and thus claim/lock stanza={0} with stanza_name={1}".format(str(stanza), str(stanza.name)))
			return False
		#sleep for 100ms to see if we have lost the claim
		time_module.sleep(lock_wait)
		claimed_stanza = stanza.from_self()
		if not claimed_stanza or claimed_stanza.worker != worker:
			if claimed_stanza:
				logger.debug("[HydraStanzaLocker] lost claim on stanza={0} with stanza_name={1} to worker={2}".format(str(stanza), stanza.name, claimed_stanza.worker))
			else:
				logger.debug("[HydraStanzaLocker] lost claim on stanza={0} with stanza_name={1} to deletion".format(str(stanza), stanza.name))
			return False
		else:
			logger.debug("[HydraStanzaLocker] successfully claimed stanza=%s with stanza_name=%s for worker=%s", str(stanza), stanza.name, claimed_stanza.worker)
			return True

def releaseStanzaLock(stanza, worker, logger):
		"""
		Unlock a conf stanza currently locked with your worker's name.
		Note that this method should only be used locally.
		Note that this method will also implicitly save the current model if successful.
		args:
			stanza - the SOLNAppObjModel based model instance for the desired stanza with a worker field
			worker - the full name for the worker locking the stanza
			logger - a logger instance

		RETURNS True if able to unlock or currently unlocked, False if under someone else's claim
		"""
		if not isinstance(stanza, SOLNAppObjModel):
			raise TypeError("Attempted to unlock a stanza that was not a SOLNAppObjModel stanza={0}".format(str(stanza)))
		if not "worker" in stanza.model_fields:
			raise TypeError("Attempted to unlock a stanza that didn't have a worker field stanza={0}".format(str(stanza)))
		if stanza.worker != worker and stanza.worker != "unassigned":
			logger.warning("[HydraStanzaLocker] Just tried to unlock a stanza that was not locked under this worker stanza_name={0} actual worker={1}".format(stanza.name, stanza.worker))
			return False
		if stanza.worker == "unassigned":
			logger.debug("[HydraStanzaLocker] Just tried to unlock an already unlocked/unclaimed stanza, whatevs it's just weird")
			return True
		#alright now we actually remove the claim
		stanza.worker = "unassigned"
		return stanza.passive_save()

def isSplunkSessionKeyValid(host_path, session_key, return_status=False):
	"""
	Determine if the given session key is valid for the particular splunk server.
	If you do not pass a session key, this will always return False, not use the default session key.
	Also this is a way to "touch" a session key, and keep it from timing out.
	If return_status is True, return the actual status code of the request, or False if host is unreachable.
	args:
		host_path - the path to the management port of the splunk server, e.g. https://idx.splunk.com:8089
		session_key - the actual session key to test
		return_status - return the actual status code of the request, False if host is unreachable

	RETURNS True if session key is valid, False otherwise or response status code
	"""
	uri = host_path.rstrip("/") + "/services/authentication/current-context"
	retval = False
	if not session_key:
		return retval
	if not host_path:
		return retval
	try:
		response, content = rest.simpleRequest(uri, sessionKey=session_key, rawResult=True)
		del content
	except Exception:
		return False
	if response.status == 200:
		retval = True

	return retval if not return_status else response.status

########################################################################
# COMMUNICATION WITH SPLUNKD
# We provide a class for printing data out to splunkd. Essentially this
# is just a wrapper on using xml formatted data delivery to splunkd
########################################################################
class XMLOutputManager(object):
	"""
	This guy handles writing data to splunkd with modular input xml
	streaming mode.
	"""
	def __init__(self, out=sys.stdout):
		"""
		Construct an output manager.
		kwargs:
			out - represents the stream to print to. Defaults to sys.stdout.
		"""
		self.stream_initiated = False
		self.out = out

	def initStream(self):
		"""
		Initiate a stream of data for splunk to consume.
		This MUST be called before any call to sendData.
		"""
		self.out.write("<stream>")
		self.stream_initiated = True

	def finishStream(self):
		"""
		Close the stream of data for splunk to consume
		"""
		if self.stream_initiated:
			self.out.write("</stream>")
			self.stream_initiated = False

	def sendData(self, buf, unbroken=None, sourcetype=None, source=None, host=None, time=None, index=None):
		"""
		Send some data to splunk
		args:
			buf - the buffer of data to send (string). REQUIRED.
		kwargs:
			unbroken - this is a boolean indicating the buf passed is unbroken data if this is True.
			           Defaults to False (buf is a single event).
			sourcetype - the sourcetype to assign to the event (string). Defaults to input default.
			source - the source to assign to the event (string). Defaults to input default.
			host - the host to assign to the event (string). Defaults to input default.
			time - the time to assign to the event (string of UTC UNIX timestamp,
			       miliseconds supported). Defaults to letting splunkd work it out.
			index - the index into which the data should be stored. Defaults to the input default.
		"""
		if not unbroken:
			self.out.write("<event>")
		else :
			self.out.write("<event unbroken=\"1\">")
		self.out.write("<data>")
		self.out.write(xml.sax.saxutils.escape(buf))
		self.out.write("</data>")
		if sourcetype is not None:
			self.out.write("<sourcetype>" + xml.sax.saxutils.escape(sourcetype) + "</sourcetype>")
		if source is not None:
			self.out.write("<source>" + xml.sax.saxutils.escape(source) + "</source>")
		if time is not None:
			if type(time) is datetime.datetime:
				time = str(time_module.mktime(time.timetuple()))
			self.out.write("<time>" + xml.sax.saxutils.escape(time) + "</time>")
		if host is not None:
			self.out.write("<host>" + xml.sax.saxutils.escape(host) + "</host>")
		if index is not None:
			self.out.write("<index>" + xml.sax.saxutils.escape(index) + "</index>")
		self.out.write("</event>\n")
		self.out.flush()

	def sendDoneKey(self, sourcetype=None, source=None, host=None, time=None, index=None):
		"""
		Let splunkd know that previously sent, unbroken events are now complete
		and ready for processing. Typically you will send some data, like chunks of a log file
		then when you know you are done, say at the end of the log file you will send a
		done key to indicate that sent data may be processed for the provided source,
		sourcetype, host, and index
		kwargs:
			sourcetype - the sourcetype of the event (string). Defaults to input default.
			source - the source of the event (string). Defaults to input default.
			host - the host of the event (string). Defaults to input default.
			index - the index into which the data is being stored. Defaults to the input default.
		"""
		self.out.write("<event unbroken=\"1\">")
		self.out.write("<data></data>")
		if sourcetype is not None:
			self.out.write("<sourcetype>" + xml.sax.saxutils.escape(sourcetype) + "</sourcetype>")
		if source is not None:
			self.out.write("<source>" + xml.sax.saxutils.escape(source) + "</source>")
		if time is not None:
			if type(time) is datetime.datetime:
				time = str(time_module.mktime(time.timetuple()))
			self.out.write("<time>" + xml.sax.saxutils.escape(time) + "</time>")
		if host is not None:
			self.out.write("<host>" + xml.sax.saxutils.escape(host) + "</host>")
		if index is not None:
			self.out.write("<index>" + xml.sax.saxutils.escape(index) + "</index>")
		self.out.write("<done/></event>\n")
		self.out.flush()

	# prints XML error data to be consumed by Splunk
	def printError(self, s):
		self.out.write("<error><message>{0}</message></error>".format(xml.sax.saxutils.escape(s)))


########################################################################
# BOILER PLATE HANDLER
# Inherit from this handler to have the minimum methods you should have
########################################################################
class HydraHandler(object):
	"""
	Abstract for a generic hydra handler for any task
	"""

	cache_model = HydraCacheStanza

	def __init__(self, output, logger, worker_name, app, gateway_adapter):
		"""
		This constructs your handler
		args:
			output - the worker's XMLOutputManager instance you use to send data to splunkd
			logger - the worker's python logger instance you use to log for your handler
			worker_name - the full name of the worker, used for locking hydra_caches
		"""
		self.logger = logger
		self.output = output
		self.worker_name = worker_name
		self.app = app
		self.gateway_adapter = gateway_adapter

	def run(self, session, config, create_time, last_time):
		"""
		This is the method you must implement to perform your atomic task
		args:
			session - the session object return by the loginToTarget method
			config - the dictionary of all the config keys from your stanza in the collection.conf
			create_time - the time this task was created/scheduled to run (datetime object)
			last_time - the last time this task was created/scheduler to run (datetime object)

		RETURNS True if successful, False otherwise
		"""
		raise NotImplementedError('Run not supported by this handler.')

	#===========================================================================
	# METHODS FOR CACHE MANAGEMENT
	# Note that cache model must be implemented to use any of these methods,
	# else the default cache handler is used
	#===========================================================================
	def getCache(self, stanza_name):
		"""
		Get the cached information for the stanza name provided. Data will be provided back as a dict.
		If the stanza does not exist yet an empty dictionary will be returned, but the stanza will
		not be created.
		args:
			stanza_name - the name under which the data is cached

		RETURNS a dict of the stanza keys:data
		"""
		#Note that we assume that session_key and host_path are local and set in the worker to global state
		model = self.cache_model.from_name(stanza_name, app=self.app)
		out_info = {}
		if model:
			for field in model.model_fields:
				out_info[field] = getattr(model, field)

		return out_info

	def getCacheAndLock(self, stanza_name):
		"""
		Get the cached information for the stanza name provided. Data will be provided back as a dict.
		Also acquire a lock on the stanza so that no other worker can edit it until it has been released.
		If the stanza does not exist yet an empty dictionary will be returned, but the stanza will
		be created.
		Also return the status of the lock, i.e. True if locked, False if unlocked
		args:
			stanza_name - the name under which the data is cached

		RETURNS a tuple of the stanza keys:data in the first index, and status (boolean) of the lock in the second
		"""
		#Note that we assume that session_key and host_path are local and set in the worker to global state
		model = self.cache_model.from_name(stanza_name, app=self.app)
		out_info = {}
		if not model:
			model = self.cache_model(self.app, "nobody", stanza_name)
			model.worker = self.worker_name
			model.last_lock_time = datetime.datetime.utcnow()
			if model.passive_save():
				return {"worker": self.worker_name, "last_lock_time": model.last_lock_time}, True
			else:
				return out_info, False
		else:
			status = acquireStanzaLock(model, self.worker_name, self.logger)
			if status:
				for field in model.model_fields:
					out_info[field] = getattr(model, field)
				out_info["worker"] = self.worker_name
			else:
				model = model.from_self()
				for field in model.model_fields:
					out_info[field] = getattr(model, field)
			return out_info, status

	def setCache(self, stanza_name, data):
		"""
		Set the cache stanza with the given name to hold data, where data is a dictionary that
		contains the keys equivalent to the model field names. Note that this requires a lock,
		if a lock cannot be acquired nothing will be set.
		args:
			stanza_name - the name under which the data is cached
			data - dict with keys equivalent to the model fields

		RETURNS True if successful, False if not
		"""
		model = self.cache_model.from_name(stanza_name, app=self.app)
		if not model:
			model = self.cache_model(self.app, "nobody", stanza_name)
		else:
			if not acquireStanzaLock(model, self.worker_name, self.logger):
				#Could not get a lock, we failed
				return False

		#We have the stanza be it new or on the lock
		for key, val in data.iteritems():
			setattr(model, key, val)
		#explicitly remove the lock, set it here first to avoid user corruption of the field
		model.worker = self.worker_name
		return releaseStanzaLock(model, self.worker_name, self.logger)

	def destroyCache(self, stanza_name, retry_count=3):
		"""
		Destroy the cache stanza named. Must be able to lock in order to destroy.
		args:
			stanza_name - the name under which the data is cached

		RETURNS True if successful False if not
		"""
		status = False
		for retry in range(retry_count):
			model = self.cache_model.from_name(stanza_name, app=self.app)
			if not model:
				status = False
			else:
				if not acquireStanzaLock(model, self.worker_name, self.logger):
					#Could not get a lock, we failed to destroy it
					status = False
				else:
					status = model.passive_delete()
			if status:
				break
		return status

