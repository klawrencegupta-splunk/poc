# Copyright (C) 2005-2017 Splunk Inc. All Rights Reserved.
#Core Python Imports
import sys
import logging, logging.handlers
from httplib2 import ServerNotFoundError
import socket, time

#CherryPy Web Controller Imports 
import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

#Splunkd imports
import splunk
import splunk.rest as rest
import splunk.util as util
import lxml.etree as et
from splunk.models.app import App

#SA Imports
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Hydra', 'bin']))
from hydra.models import HydraNodeStanza, SplunkStoredCredential

#CONSTANTS
REST_ROOT_PATH = '/services'


def setupLogger(logger=None, log_format='%(asctime)s %(levelname)s [SAHydraConfService] %(message)s', level=logging.INFO, log_name="hydra_conf_service.log", logger_name="hydra_conf_service"):
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
	
	logger.debug("init hydra conf service logger")
	
	return logger

def splunk_rest_request(path, sessionKey=None, getargs=None, postargs=None, method='GET', raiseAllErrors=False, proxyMode=False, rawResult=False, timeout=30, jsonargs=None):
	"""
	This is mostly a shameful copy of splunk.rest.simpleRequest.
	The difference lies in the automagic header/cert attachment that
	happens in splunkweb and messes with the splunkweb cherrypy.session.
	Also we don't auto magic any session keys
	
	Makes an HTTP call to the main splunk REST endpoint
	
	path: the URI to fetch
		If given a relative URI, then the method will normalize to the splunkd
		default of "/services/...".
		If given an absolute HTTP(S) URI, then the method will use as-is.
		If given a 'file://' URI, then the method will attempt to read the file
		from the local filesystem.  Only files under $SPLUNK_HOME are supported,
		so paths are 'chrooted' from $SPLUNK_HOME.
		
	getargs: dict of k/v pairs that are always appended to the URL
	
	postargs: dict of k/v pairs that get placed into the body of the 
		request. If postargs is provided, then the HTTP method is auto
		assigned to POST.
		
	method: the HTTP verb - [GET | POST | DELETE | PUT]
	
	raiseAllErrors: indicates if the method should raise an exception
		if the server HTTP response code is >= 400

	rawResult: don't raise an exception if a non 200 response is received;
		return the actual response
	
	Return:
	
		This method will return a tuple of (serverResponse, serverContent)
		
		serverResponse: a dict of HTTP status information
		serverContent: the body content
	"""
	# strip spaces
	path = path.strip(' ')
	# if absolute URI, pass along as-is
	if path.startswith('http'):
		uri = path
		
	# if file:// protocol, try to read file and return
	# the serverStatus is just an empty dict; file contents are in serverResponse
	elif path.startswith('file://'):
		raise Exception("Not supported for this method, use splunk.rest.simpleRequest instead")
			
	else:
		# prepend convenience root path
		if not path.startswith(REST_ROOT_PATH): path = REST_ROOT_PATH + '/' + path.strip('/')
		
		# setup args
		host = splunk.getDefault('host')
		if ':' in host:
			host = '[%s]' % host
			
		uri = '%s://%s:%s/%s' % \
			(splunk.getDefault('protocol'), host, splunk.getDefault('port'), path.strip('/'))

	if getargs:
		getargs = dict([(k,v) for (k,v) in getargs.items() if v != None])
		uri += '?' + util.urlencodeDict(getargs)
	
	# proxy mode bypasses all header passing
	headers = {}
	sessionSource = 'direct'
	
	if sessionKey:
		headers['Authorization'] = 'Splunk %s' % sessionKey
	
	payload = ''
	if postargs or jsonargs and method in ('GET', 'POST', 'PUT'):
		if method == 'GET':
			method = 'POST'
		if jsonargs:
			# if a JSON body was given, use it for the payload and ignore the postargs
			payload = jsonargs
		else:
			payload = util.urlencodeDict(postargs)
	#
	# make request
	#
	if logger.level <= logging.DEBUG:
		if uri.lower().find('login') > -1:
			logpayload = '[REDACTED]'
		else:
			logpayload = payload
		logger.debug('splunk_rest_request >>>\n\tmethod=%s\n\turi=%s\n\tbody=%s', method, uri, logpayload)
		logger.debug('splunk_rest_request > %s %s [%s] sessionSource=%s' % (method, uri, logpayload, sessionSource))
		t1 = time.time()

	# Add wait and tries to check if the HTTP server is up and running
	tries = 4
	wait = 10
	try:
		import httplib2
		for aTry in range(tries):
			h = httplib2.Http(timeout=timeout, disable_ssl_certificate_validation=True)
			serverResponse, serverContent = h.request(uri, method, headers=headers, body=payload)
			if serverResponse == None:
				if aTry < tries:
					time.sleep(wait)
			else:
				break
	except socket.error, e:
		raise splunk.SplunkdConnectionException, str(e)
	except socket.timeout, e:
		raise splunk.SplunkdConnectionException, 'Timed out while waiting for splunkd daemon to respond. Splunkd may be hung. (timeout=30)'
	except AttributeError, e:
		raise splunk.SplunkdConnectionException, 'Unable to establish connection with splunkd deamon. (%s)' % e

	serverResponse.messages = []
	
	if logger.level <= logging.DEBUG:
		logger.debug('simpleRequest < server responded status=%s responseTime=%.4fs', serverResponse.status, time.time() - t1)
		
	# Don't raise exceptions for different status codes or try and parse the response
	if rawResult:
		return serverResponse, serverContent

	#
	# we only throw exceptions in limited cases; for most HTTP errors, splunkd
	# will return messages in the body, which we parse, so we don't want to
	# halt everything and raise exceptions; it is up to the client to figure 
	# out the best course of action
	#
	if serverResponse.status == 401:
		#SPL-20915
		logger.debug('splunk_rest_request - Authentication failed; sessionKey=%s', sessionKey)
		raise splunk.AuthenticationFailed
	
	elif serverResponse.status == 402:
		raise splunk.LicenseRestriction
	
	elif serverResponse.status == 403:
		raise splunk.AuthorizationFailed(extendedMessages=uri)
		
	elif serverResponse.status == 404:
		
		# Some 404 responses, such as those for expired jobs which were originally
		# run by the scheduler return extra data about the original resource.
		# In this case we add that additional info into the exception object
		# as the resourceInfo parameter so others might use it.
		try:
			body = et.fromstring(serverContent)
			resourceInfo = body.find('dict')
			if resourceInfo is not None:
				raise splunk.ResourceNotFound(uri, format.nodeToPrimitive(resourceInfo))
			else:
				raise splunk.ResourceNotFound(uri, extendedMessages=rest.extractMessages(body))
		except et.XMLSyntaxError:
			pass
		
		raise splunk.ResourceNotFound, uri
	
	elif serverResponse.status == 201:
		try:
			body = et.fromstring(serverContent)
			serverResponse.messages = rest.extractMessages(body)
		except et.XMLSyntaxError, e:
			# do nothing, just continue, no messages to extract if there is no xml
			pass
		except e:
			# warn if some other type of error occurred.
			logger.warn("exception trying to parse serverContent returned from a 201 response.")
			pass
		
	elif serverResponse.status < 200 or serverResponse.status > 299:
		
		# service may return messages in the body; try to parse them
		try:
			body = et.fromstring(serverContent)
			serverResponse.messages = rest.extractMessages(body)
		except:
			pass
			
		if raiseAllErrors and serverResponse.status > 399:
			
			if serverResponse.status == 500:
				raise splunk.InternalServerError, (None, serverResponse.messages)
			elif serverResponse.status == 400:
				raise splunk.BadRequest, (None, serverResponse.messages)
			else:
				raise splunk.RESTException, (serverResponse.status, serverResponse.messages)
			

	# return the headers and body content
	return serverResponse, serverContent

def getRemoteSessionKey(username, password, hostPath):
	'''
	Get a remote session key from the auth system
	If fails return None
	'''
	
	uri = splunk.mergeHostPath(hostPath) + '/services/auth/login'
	args = {'username': username, 'password': password }
	
	try:
		serverResponse, serverContent = splunk_rest_request(uri, postargs=args)
	except splunk.AuthenticationFailed:
		return None
	
	if serverResponse.status != 200:
		logger.error('getRemoteSessionKey - unable to login; check credentials')
		rest.extractMessages(et.fromstring(serverContent))
		return None

	root = et.fromstring(serverContent)
	sessionKey = root.findtext('sessionKey')
	
	
	return sessionKey


logger = setupLogger()
splunk.setDefault()
local_host_path = splunk.mergeHostPath()

class HydraConfError(cherrypy.HTTPError):
	"""
	Use this to set the status and msg on the response.
	Call this like:
		raise HydraConfError(status=500, message="well we snafu'd a bit there")
	"""
	def get_error_page(self, *args, **kwargs):
		kwargs['noexname'] = 'true'
		return super(HydraConfError, self).get_error_page(*args, **kwargs)

class hydra_conf_service(controllers.BaseController):
	'''SA-Hydra Configuration Service Controller'''

	def __init__(self):
		self._prevent_validation_save = False
		super(hydra_conf_service, self).__init__()
	
	def _get_node_stanza(self, app, node_path, local_session_key):
		"""
		Attempt to get a stanza instance from stanza name (node_path), if the attempt fails,
		create a new stanza.
		"""
		node_stanza = HydraNodeStanza.from_name(node_path, app, "nobody", session_key=local_session_key, host_path=local_host_path)
		if not node_stanza:
			node_stanza = HydraNodeStanza(app, "nobody", node_path, sessionKey=local_session_key, host_path=local_host_path)
			node_stanza.host = node_path
		return node_stanza
		
	def _save_validation_fields(self, node_stanza, creds=False, addons=False):
		if not self._prevent_validation_save:
			node_stanza.credential_validation = creds
			node_stanza.addon_validation = addons
			if not node_stanza.passive_save():
				logger.error("[_save_validation_fields] Error saving validation information for node={0}".format(node_stanza.name))
		
	def _validate_collection_node(self, app, node_path, node_username=False, node_password=False):
		"""
		validates the given hydra collection node's credentials
		ARGS:
			app - app namespace to get the data from
			node_path - the stanza name to validate (for hydra nodes, stanza name == node path)
			username - optional, if passed will use this username to validate
			password - optional, if passed will use this password to validate
			
		RETURNS a {'status': STATUS, 'msg': MSG} dict to be used with 
		        the controller's render_json() method
		"""
		LOG_PREFIX = "[_validate_collection_node] "
		local_session_key = cherrypy.session["sessionKey"]
		response = {}
		node_stanza = self._get_node_stanza(app, node_path, local_session_key)
		# if the username is supplied but doesn't match the one saved in the stanza,	
		# we still run validation, but we don't save the validation results:
		# saved results must correspond to saved credentials
		# we achieve this via an instance-level flag
		self._prevent_validation_save = bool(node_username and node_username != node_stanza.user)
		if not node_username or not node_password:
			node_username = node_stanza.user
			node_password = SplunkStoredCredential.get_password(node_path, node_username, app, session_key=local_session_key, host_path=local_host_path)
			if node_password is None:
				self._save_validation_fields(node_stanza, creds=False, addons=False)
				response = {"status":"invalid", "msg":"No password found for this node please save a password"}
				return response
		#Time to actually validate the credentials!
		try:
			remote_session_key = getRemoteSessionKey(node_username, node_password, hostPath=node_path)
			if remote_session_key is None:
				#This is a big old fail
				response = {"status" : "invalid", "msg":"Could reach host, but login failed"}
				self._save_validation_fields(node_stanza, creds=False, addons=False)
			else:
				#Okay credentials are good, now we can check that the apps are there
				apps = App.all(host_path=node_path, sessionKey=remote_session_key)
				required_apps = ["SA-VMNetAppUtils", "SA-Hydra"]
				installed_count = 0
				installed_apps = []
				for app in apps:
					installed_apps.append(app.label)
					if app.name in required_apps:
						installed_count += 1
				if installed_count == len(required_apps):
					response = {"status" : "valid", "msg":"Everything is valid"}
					self._save_validation_fields(node_stanza, creds=True, addons=True)
				else:
					logger.warning(LOG_PREFIX + "node did not have the required apps, it had installed_apps='{0}'".format(str(installed_apps)))
					response = {"status" : "badapps", "msg":"Username/password are good but apps are not there"}
					self._save_validation_fields(node_stanza, creds=True, addons=False)
		except ServerNotFoundError:
			response = {"status" : "unreachable", "msg":"Could not reach host"}
		except splunk.SplunkdConnectionException:
			logger.error("Could not find splunkd on node=%s", node_path)
			response = {"status" : "unreachable", "msg":"Could not reach host"}
		except splunk.AuthenticationFailed:
			logger.error("Could not log into splunkd on node=%s, credentials are definitely bad", node_path)
			response = {"status" : "invalid", "msg":"Could not authenticate with remote splunkd"}
		except Exception:
			response = {"status" : "unreachable", "msg":"Could not reach host"}
		finally:
			return response
		

	@route('/:app/:action=validate_collection_node')
	@expose_page(must_login=True, methods=['GET'])
	def validate_collection_node(self, app, action, **kwargs):
		"""
		Given the node, determine several things. First, is it routeable? Next,
		is the provided username/password able to log in? Finally does it have 
		the required add-ons?
		To interact with this endpoint the node must already be stored in 
		hydra_node.conf. 
		REQUEST PARAMS:
			REQUIRED:
			node - the host path (management uri) of the node to be tested
			OPTIONAL (only used if both are passed):
				username - the username to validate
				password - the password to validate
		RESPONSE:
			All responses, unless uncaught error occurs are json with 
			a status and message field
			status - msg
			valid - Everything is valid
			unreachable - Could not reach the node to test creds
			invalid - Could reach host, but login failed
			badapps - Username/password are good but apps are not there
		"""
		LOG_PREFIX = "[validate_collection_node] "
		logger.debug(LOG_PREFIX + "starting validation")
		node_path = kwargs.get("node", False)
		if not node_path:
			logger.error(LOG_PREFIX + "No node name passed to validate_collection_node, cannot validate nothing!")
			raise HydraConfError(status="500", message="No node name passed to validate_collection_node, cannot validate nothing!")
		username = kwargs.get("username", False)
		password = kwargs.get("password", False)
		response = self._validate_collection_node(app, node_path, username, password)
		return self.render_json(response)

	@route('/:app/:action=save_collection_node')
	@expose_page(must_login=True, methods=['POST'])
	def save_collection_node(self, app, action, **kwargs):
		"""
		Given the node info, save the worker node to hydra_node.conf
		REQUEST PARAMS:
			REQUIRED:
			node_name - the name of the node stanza being edited, if empty string means create new
			node - the management uri
			username - user to use with node
			password - password to use with node
			heads - number of input processes to enable
		RESPONSE:
			200 (update), 201 (created) or 500 (error)
		"""
		node_path = kwargs.get("node", False)
		node_name = kwargs.get("node_name", node_path)
		if not node_path:
			logger.error("No node name passed to save_worker_node, cannot save nothing!")
			raise HydraConfError(status="500", message="No node name passed to save_worker_node, cannot save nothing!")
		username = kwargs.get("username", False)
		if not username:
			logger.error("No username passed to save_worker_node, cannot save nothing!")
			raise HydraConfError(status="500", message="No username passed to save_worker_node, cannot save nothing!")
		heads = kwargs.get("heads", False)
		if not heads:
			logger.error("No heads passed to save_worker_node, cannot save nothing!")
			raise HydraConfError(status="500", message="No heads passed to save_worker_node, cannot save nothing!")
		password = kwargs.get("password", False)
		if not password:
			logger.info("No password passed to save_worker_node, will not edit password")
		#First try to pull up an existing conf stanza
		local_session_key = cherrypy.session["sessionKey"]
		status = 200
		#First we check if we have to delete an old node due to changing the path
		if node_name and (node_name != node_path):
			node_stanza = HydraNodeStanza.from_name(node_name, app, host_path=local_host_path, session_key=local_session_key)
			logger.info("collection node's old_host_path=%s edited will delete existing stanza and create new one with new_host_path=%s. also deleting associated credential", node_name, node_path)
			if not node_stanza.passive_delete():
				logger.error("Could not delete hydra node stanza with host_path={0}".format(node_name))
			node_stanza = False
		else:
			node_stanza = HydraNodeStanza.from_name(node_path, app, host_path=local_host_path, session_key=local_session_key)
		if not node_stanza:
			logger.info("creating new hydra node stanza for host_path={0}".format(node_path))
			node_stanza = HydraNodeStanza(app, "nobody", node_path, sessionKey=local_session_key, host_path=local_host_path)
			status = 201
			cherrypy.response.headers["Location"] = node_stanza.get_id()
		if node_stanza.user != username:
			#Need to redo the password for new username
			stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(node_name, str(node_stanza.user)), app=app, owner="nobody", host_path=local_host_path, session_key=local_session_key)
			if stored_cred:
				if not password:
					password = stored_cred.clear_password
					logger.info("Recreating secure storage of password for collection_node={0}".format(node_path))
				logger.info("Deleting outmoded credential")
				if not stored_cred.passive_delete():
					logger.error("Could not delete outmoded credential it may linger")
		if password:
			new_cred = SplunkStoredCredential(app, "nobody", username, sessionKey=local_session_key, host_path=local_host_path)
			new_cred.realm = node_path
			new_cred.password = password
			new_cred.username = username
			if not new_cred.passive_save():
				logger.error("Failed to save credential: realm={0} username={1}".format(node_path, username))
		else:
			password = SplunkStoredCredential.get_password(node_path, username, app, session_key=local_session_key, host_path=local_host_path)
		node_stanza.host = node_path
		node_stanza.user = username
		node_stanza.heads = heads
		
		#Cannot edit heads without knowing the input name, so no luck on this here. 
		#Manipulate the inputs on the remote node to match heads if able, otherwise log error but otherwise do nothing
#		input_names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]
#		try:
#			remote_session_key = getRemoteSessionKey(username, password, node_path)
#		except ServerNotFoundError:
#			logger.error("Could not find node=%s", node_path)
#			remote_session_key = None
#		except splunk.SplunkdConnectionException:
#			logger.error("Could not find splunkd on node=%s", node_path)
#			remote_session_key = None
#		except splunk.AuthenticationFailed:
#			logger.error("Could not log into splunkd on node=%s, credentials are definitely bad", node_path)
#			remote_session_key = None
#		except Exception:
#			remote_session_key = None
#		if remote_session_key is None:
#			logger.error("Could not log into node=%s with the credentials provided, cannot manage the heads on that node", node_path)
#			node_stanza.credential_validation = False
#		else:
#			for counter in range(len(input_names)):
#				input_name = input_names[counter]
#				if counter < int(heads):
#					action = "enable"
#				else:
#					action = "disable"
#				path = node_path.rstrip("/") + "/servicesNS/nobody/Splunk_TA_vmware/data/inputs/ta_vmware_collection_worker/" + input_name + "/" + action
#				try:
#					logger.info("Adjusting input with rest request on path=%s with session_key=%s", path, remote_session_key)
#					splunk_rest_request(path, sessionKey=remote_session_key, method="POST", raiseAllErrors=True)
#				except ServerNotFoundError:
#					logger.exception("Could not reach node={0}", node_path)
#				except Exception as e:
#					message = "Problem editing the number of worker inputs on the remote node={0}: ".format(node_path) + e.message
#					logger.exception(message)
#					node_stanza.addon_validation = False
		
		if node_stanza.passive_save():
			cherrypy.response.status = status
			self._validate_collection_node(app, node_path, username, password)
		else:
			raise HydraConfError(status=500, message="Could not save node={0}".format(node_path))
	
	
	@route('/:app/:action=delete_collection_node/:node_path')
	@expose_page(must_login=True, methods=['DELETE'])
	def delete_collection_node(self, app, action, node_path, **kwargs):
		"""
		Given the node info, delete the worker node from hydra_node.conf
		REQUEST PARAMS:
			REQUIRED:
			node - the management uri
		RESPONSE:
			200 (deleted) or 500 (error)
		"""
		if not node_path:
			logger.error("No node name passed to save_worker_node, cannot save nothing!")
			raise HydraConfError(status="500", message="No node name passed to delete_worker_node, cannot delete nothing!")
		local_session_key = cherrypy.session["sessionKey"]
		node_stanza = HydraNodeStanza.from_name(node_path, app, host_path=local_host_path, session_key=local_session_key)
		if node_stanza:
			node_username = node_stanza.user
			stored_cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(node_stanza.host, node_stanza.user), app=app, owner="nobody", host_path=local_host_path, session_key=local_session_key)
			if stored_cred:
				node_password = stored_cred.clear_password
				logger.info("Deleting obsolete credential")
				if not stored_cred.passive_delete():
					logger.error("Could not delete obsolete credential it may linger")
			else:
				node_password = None
			if not node_stanza.passive_delete():
				raise HydraConfError(status="500", message="Failed to delete node {0}".format(node_path))
		else:
			raise HydraConfError(status="500", message="Failed to find node {0}, cannot delete it".format(node_path))
		
		try:
			remote_session_key = getRemoteSessionKey(node_username, node_password, node_path)
		except ServerNotFoundError:
			logger.error("Could not find node=%s", node_path)
			remote_session_key = None
		except splunk.SplunkdConnectionException:
			logger.error("Could not find splunkd on node=%s", node_path)
			remote_session_key = None
		except splunk.AuthenticationFailed:
			logger.error("Could not log into splunkd on node=%s, credentials are definitely bad", node_path)
			remote_session_key = None
		except Exception:
			remote_session_key = None
		if remote_session_key is None:
			logger.error("Could not log into node=%s with the credentials provided, cannot manage the heads on that node", node_path)
		else:
			#CANNOT EDIT INPUTS WITHOUT KNOWING THE NAME OF SAID INPUT
			#Manipulate the inputs on the remote node, i.e. disable them all
#			input_names = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta"]
#			for input_name in input_names:
#				action = "disable"
#				path = node_path.rstrip("/") + "/servicesNS/nobody/Splunk_TA_vmware/data/inputs/ta_vmware_collection_worker/" + input_name + "/" + action
#				try:
#					logger.info("Adjusting input with rest request on path=%s", path)
#					splunk_rest_request(path, sessionKey=remote_session_key, method="POST", raiseAllErrors=True)
#				except ServerNotFoundError:
#					logger.exception("Could not reach node={0} to edit hydra worker inputs", node_path)
#				except Exception as e:
#					message = "Problem editing the number of worker inputs on the remote node={0}: ".format(node_path) + e.message
#					logger.exception(message)
			#Destroy stored credentials
			try:
				creds = SplunkStoredCredential.all(host_path=node_path, sessionKey=remote_session_key)
				creds._owner = "nobody"
				creds.filter_by_app(app)
				for cred in creds:
					if not cred.passive_delete():
						logger.error("Problem deleteing credential on node={0}".format(node_path))
			except ServerNotFoundError:
				logger.exception("Could not reach node={0} to delete all credentials under %s", node_path, app)
			except Exception as e:
				message = "Problem deleting the stored credentials on the remote node={0}: ".format(node_path) + e.message
				logger.exception(message)
