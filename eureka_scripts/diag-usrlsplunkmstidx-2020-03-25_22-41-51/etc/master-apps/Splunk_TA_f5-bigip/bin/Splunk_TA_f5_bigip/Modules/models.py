#All models for hydra configuration stanzas and required extras
#Core python imports
from csv import reader
from base64 import b64encode, b64decode
from collections import namedtuple
import cPickle
import urllib
import datetime
import logging
import re

#Splunk Imports
import splunk.rest
from splunk.entity import buildEndpoint as buildEntityEndpoint
from splunk import ResourceNotFound,auth
from splunk.models.base import SplunkAppObjModel, SplunkRESTManager, SplunkQuerySet
from splunk.models.field import Field, IntField, BoolField


logger = logging.getLogger('splunk.models.base')

########################################################################
# FIELDS
########################################################################
class CSVField(Field):
    '''
    Represents a list/array structure that assumes csv
    '''

    def from_apidata(self, api_dict, attrname):
        val = super(CSVField, self).from_apidata(api_dict, attrname)
        if not isinstance(val, list):
            try:
                r = reader([val], skipinitialspace=True)
                return r.next()
            except TypeError:
                return []
        return val

    def to_apidata(self, attrvalue):
        if not isinstance(attrvalue, list):
            raise TypeError, 'CSVField must be a list construct'
        return ', '.join(attrvalue)

class ISODateTimeField(Field):
    '''
    Represents a time field stored as an ISO 8601 and returned as a python
    datetime object. This does not support timezones, timestamps stored here
    are meant to be representative of naive datetime objects in python. As a
    best practice only UTC timestamps should be stored in fields of this type.
    For reference the expected formats are:
        %Y-%m-%dT%H:%M:%S.%f OR %Y-%m-%dT%H:%M:%S
    E.G.:
        2013-03-06T00:44:43.962619
    '''

    def from_apidata(self, api_dict, attrname):
        val = super(ISODateTimeField, self).from_apidata(api_dict, attrname)
        if not isinstance(val, datetime.datetime):
            try:
                return datetime.datetime.strptime(val, '%Y-%m-%dT%H:%M:%S.%f')
            except TypeError:
                #if there is nothing, e.g. constructing a new item, we get TypeError
                return datetime.datetime.fromtimestamp(0)
            except ValueError:
                #support timestamps without fractional seconds
                return datetime.datetime.strptime(val, '%Y-%m-%dT%H:%M:%S')
        return val

    def to_apidata(self, attrvalue):
        if not isinstance(attrvalue, datetime.datetime):
            raise TypeError, 'ISODateTimeField must be a datetime.datetime construct'
        return attrvalue.isoformat()

class PythonObjectField(Field):
    '''
    Represents an arbitrary python object, CANNOT BE A STRING, use Field for strings
    '''

    def from_apidata(self, api_dict, attrname):
        val = super(PythonObjectField, self).from_apidata(api_dict, attrname)
        if isinstance(val, str):
            try:
                obj = cPickle.loads(b64decode(val))
                return obj
            except TypeError:
                return dict()
        return val

    def to_apidata(self, attrvalue):
        if not isinstance(attrvalue, str):
            return b64encode(cPickle.dumps(attrvalue))
        else:
            return attrvalue

#DEPRECATED! use class in hydra_common.py
JobTuple = namedtuple("JobTuple", "target task metadata_id create_time last_time expiration_period special")
class HydraJobField(Field):
    '''
    These fields represent hydra jobs and have the format:
    <task>|<metadata-id>|<create_time>|<last_time>|<expiration_period(seconds)>|special
    where:
        task - The type of job to be executed, which matches the capability of a worker that can execute it
        metadata-id - the identifier of the metadata (collection conf) to do this job under
        create_time - The creation time of the job (i.e. the time scheduled to run)
        last_time - The last create_time of the same config token
        expiration_period -  Token expiry time in sec
        special -  special args
    '''
    @classmethod
    def _convert_ISODateTime(cls, val):
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
    @classmethod
    def _parse_special(cls, val):
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

    @classmethod
    def _dump_special(cls, val):
        """
        Python Object Field parsing for one part of job Tuple
        """
        if not isinstance(val, str):
            return b64encode(cPickle.dumps(val))
        else:
            return val

    def from_apidata(self, api_dict, attrname):
        val = super(HydraJobField, self).from_apidata(api_dict, attrname)
        if isinstance(val, str):
            prop_list = val.split("|", 6)
            if len(prop_list) == 7:
                return JobTuple(
                    prop_list[0],
                    prop_list[1],
                    prop_list[2],
                    self._convert_ISODateTime(prop_list[3]),
                    self._convert_ISODateTime(prop_list[4]),
                    prop_list[5],
                    self._parse_special(prop_list[6])
                    )
            else:
                raise ValueError("Jobs must be of format <target>|<task>|<metadata-id>|<create_time>|<last_time>|<expiration_period(seconds)>|<special>, i.e. 7 values")
        else:
            raise TypeError("Job fields cannot be None, must be strings of the form <target>|<task>|<metadata-id>|<create_time>|<last_time>|<expiration_period(seconds)>|<special>, i.e. 7 values")

    def to_apidata(self, attrvalue):
        if isinstance(attrvalue, JobTuple):
            return "|".join([attrvalue.target, attrvalue.task, attrvalue.metadata_id, self._convert_ISODateTime(attrvalue.create_time), self._convert_ISODateTime(attrvalue.last_time), str(attrvalue.expiration_period), self._dump_special(attrvalue.special)])
        elif attrvalue == "":
            return attrvalue
        else:
            raise TypeError("Values of hydra job fields must be namedtuples of type JobTuple")

########################################################################
# ABSTRACT MODEL CLASSES
########################################################################

#This is a named tuple type used to specify wildcard fields, see SOLNAppObjModel
WildcardField = namedtuple("Wildcardfield", "pattern field_class")

class SOLNQuerySet(SplunkQuerySet):
    '''
    Override and add methods as workaround for core issues within SplunkAppObjModel
        SPL-61482
    Essentially the SplunkQuerySet object is the most common way we generate collections
    of models. The problem is that the models returned from its iterator are made from
    entity and are not given the session key. Thus they will always rely on the default
    session key set by setDefault. The issue with that is that if you are managing a
    remote splunk instance your session key is incorrect. Thus you get models with data
    but with no ability to take any actions.
    We fix that by causing the SOLNAppObjModel to return a SOLNQuerySet with a modified
    iterator which assigns the session key into the models.
    '''

    def iterator(self):
        '''
        The actual iterator itself.  Will retrieve the entities for a given
        resource in pages based on the internal count_per_req.
        '''

        # Set the count to the lesser of the count_per_req or the internal
        # count. This remains constant until the very last req.
        iter_count = self._count_per_req if (self._count > self._count_per_req or self._count == 0) else self._count

        # The initial iterator offset is the same as the queryset's.
        iter_offset = self._offset

        # Get the initial set of entities so we can start somewhere and have
        # access to the total # of entities.
        try:
            entities = self.get_entities(count=iter_count, offset=iter_offset, search=self._search_string, sort_key=self._sort_key, sort_dir=self._sort_dir, hostPath=self._host_path, sessionKey=self._sessionKey)
        except splunk.AuthenticationFailed:
            raise
        except splunk.LicenseRestriction:
            raise splunk.LicenseRestriction
        except Exception:
            #logger.warn('Could not retrieve entities for the given resource with the following error %s' % e)
            self.total = 0
            return

        results = [self.manager._from_entity(self.manager._fix_entity(entities[entity])) for entity in entities]

        # Get the actual total, even though this may be a slice
        self.total = int(entities.totalResults)
        max_num_iters = self.total / iter_count

        # Now determine the final offset so we can setup a while loop
        # over the offset (essentially page)
        # self._count being greater than 0 indicates this is a slice
        num_iters = (self._count / iter_count if self._count else (self.total / iter_count)) - 1
        remainder =  self._count % iter_count if self._count else (self.total % iter_count)

        # ensure that requesting a count greater than total number of results
        # doesn't produce excess requests
        num_iters = min(max_num_iters, num_iters)

        if remainder: num_iters += 1

        # Yield the initial set of models
        for model in results:
            model.sessionKey = self._sessionKey
            yield model

        while num_iters > 0:
            num_iters -=1

            iter_offset = iter_count + iter_offset
            if num_iters == 0:
                # only change iter_count if page size is non-default
                iter_count = remainder or iter_count

            entities = self.get_entities(count=iter_count, offset=iter_offset, search=self._search_string, sort_key=self._sort_key, sort_dir=self._sort_dir, hostPath=self._host_path, sessionKey=self._sessionKey)
            results = [self.manager._from_entity(self.manager._fix_entity(entities[entity])) for entity in entities]

            for model in results:
                model.sessionKey = self._sessionKey
                yield model

class SOLNRESTManager(SplunkRESTManager):
    """
    Override and add methods as workaround for core issues within SplunkRESTManager
        SPL-62571
    Also we want to be able to enforce an _new specification with simple model fields
    """
    def _get_entity(self, mid, host_path=None):
        """Loads an entity given an id."""

        #note we only add the host_path to uri if it is not fully qualified and we have a host_path
        if mid.startswith("/services"):
            if host_path:
                mid = host_path.rstrip('/') + mid
            elif self.host_path is not None:
                mid = self.host_path.rstrip('/') + mid

        host_path = host_path or self.host_path
        return self._fix_entity(splunk.entity.getEntity(self.model.resource, None, sessionKey=self.sessionKey, uri=mid, hostPath=host_path))

    def _from_entity(self, entity):
        """Construct this model from an entity."""

        obj = self.model(entity.namespace, entity.owner, entity.name, entity)
        obj.from_entity(entity)

        #Stick in the host_path and sessionKey so that we can still work remote
        if obj.host_path is None and self.host_path is not None:
            obj.host_path = self.host_path
        if obj.sessionKey is None and self.sessionKey is not None:
            obj.sessionKey = self.sessionKey

        return obj

    def _matches_any(self, field, wildcardFields, precompiled=False):
        if precompiled:
            for fieldRegex in wildcardFields:
                if fieldRegex.match(field):
                    return True
        else:
            for fieldRegex in wildcardFields:
                if re.match(fieldRegex, field):
                    return True
        return False

    def _put_entity(self, eid, entity, messages=None, sessionKey=None):
        """Saves an entity given an id."""

        messages = messages or []

        postargs = entity.getCommitProperties()

        if isinstance(eid, str) and eid.startswith("/") and isinstance(entity.hostPath, str) and entity.hostPath.startswith("http"):
            eid = entity.hostPath.rstrip("/") + eid

        # EAI endpoints dynamically declare required and optional fields
        # that can be POSTed. Make sure that we validate against args
        try:
            if self.model.use_model_as_spec:
                allow_fields = self.model.get_mutable_fields()
                allow_fields.extend(['name'])
                wildcard_fields = []
                precompiled = True
                for wildcard_field in self.model.wildcard_fields.itervalues():
                    wildcard_fields.append(wildcard_field.pattern)
            else:
                entity_template = self._get_new_entity(namespace=entity.namespace, owner=entity.owner, sessionKey=sessionKey)
                allow_fields = entity_template['eai:attributes']['optionalFields']
                allow_fields.extend(entity_template['eai:attributes']['requiredFields'])
                precompiled = False
                wildcard_fields = entity_template['eai:attributes']['wildcardFields']

            to_delete = []
            for arg in postargs:
                if arg not in allow_fields and not self._matches_any(arg, wildcard_fields, precompiled) and not arg.startswith('eai:'):
                    messages.append('disallowed field being posted, removing: %s' % arg)
                    to_delete.append(arg)
            for arg in to_delete:
                del postargs[arg]
        except Exception as e:
            logger.exception(e)

        return self._put_args(eid, postargs, messages, sessionKey=sessionKey)

    def _put_args(self, eid, postargs, messages=None, sessionKey=None):
        """
        Posts arguments and returns the entity or messages.
        Overloaded to enable updating on existing entities.
        """

        messages = messages or []

        logger.debug('url path: %s' % id)
        logger.debug('body: %s' % postargs)

        serverResponse, serverContent = splunk.rest.simpleRequest(eid, postargs=postargs, raiseAllErrors=False, sessionKey=sessionKey)

        if serverResponse.status == 409:
            logger.warning("Tried to create an entity that already existed, will attempt update instead")
            eid = eid.rstrip("/") + "/" + postargs["name"]
            del postargs["name"]
            serverResponse, serverContent = splunk.rest.simpleRequest(eid, postargs=postargs, raiseAllErrors=True, sessionKey=sessionKey)

        if serverResponse.status not in [200, 201]:
            messages.append(serverResponse.messages)
            raise splunk.RESTException("unsuccessful in saving entity=%s", eid)
            return None

        try:
            atomEntry = splunk.rest.format.parseFeedDocument(serverContent)
        except Exception, e:
            messages.append({'text': 'Unable to parse feed.', 'type': 'ERROR'})
            return None

        if isinstance(atomEntry, splunk.rest.format.AtomFeed):
            try:
                atomEntry = atomEntry[0]
            except IndexError, e:
                messages.append({'text': 'Empty response.', 'type': 'ERROR'})
                return None

        entity = splunk.entity.Entity(self.model.resource, '', atomEntry.toPrimitive(), 'search')

        try:
            entity.owner = atomEntry.author
            entity.updateTime = atomEntry.updated
            entity.summary = atomEntry.summary
            entity.links = atomEntry.links
            entity.id = atomEntry.id
            entity.name = atomEntry.title
            entity.hostPath = None
        except AttributeError, e:
            messages.append({'text': 'AtomEntry missing property: %s.' % e, 'type': 'ERROR'})
            return None

        return entity

class SOLNAppObjModel(SplunkAppObjModel):
    '''
    Override and add methods as workaround for core issues within SplunkAppObjModel
        SPL-61482, SPL-62571
    Also provide a more intuitive get functionality where you specify app, owner, etc.
    Also allow models to state that they are the conf specification
    Also allow models to specify wildcard fields:
        the property wildcard_fields must be a dict of WildcardField namedtuples.
        The dict keys will determine the name for the collection of fields that match the given pattern
        The dict values are the WildcardField namedtuples
        WildcardField namedtuples have the structure:
            pattern - compiled python regex, e.g. re.compile("job_\d+")
            field_class - a class instance that inherits from Field that describes instances of these fields
    '''
    use_model_as_spec = False

    wildcard_fields = {}

    @classmethod
    def all(cls, namespace=None,default_owner='-', *args, **kwargs):
        """
        Gets us SOLNQuerySets instead of SplunkQuerySets as per normal
        Note that the kwargs allow for host_path and sessionKey to be set for remote hosts
        """
        manager = SOLNRESTManager(cls, **kwargs)
        sqs=SOLNQuerySet(manager, **kwargs)
        # can set namespace='-' here so that stanzas in different namespace will not be merged
        sqs._namespace=namespace
        sqs._owner=auth.getCurrentUser()['name']
        if sqs._owner=='UNDEFINED_USERNAME':
            sqs._owner=default_owner
        return sqs.all(*args, **kwargs)

    @classmethod
    def manager(cls, sessionKey=None, host_path=None):
        return SOLNRESTManager(cls, sessionKey=sessionKey, host_path=host_path)

    @classmethod
    def get(cls, mid=None, sessionKey=None, host_path=None):
        return SOLNRESTManager(cls, sessionKey=sessionKey, host_path=host_path).get(mid)

    @classmethod
    def order_by(cls, *args, **kwargs):
        """Note that the kwargs allow for host_path and sessionKey to be set for remote hosts"""
        return SOLNRESTManager(cls, **kwargs).order_by(*args, **kwargs)

    @classmethod
    def search(cls, *args, **kwargs):
        """Note that the kwargs allow for host_path and sessionKey to be set for remote hosts"""
        return SOLNRESTManager(cls, **kwargs).search(*args, **kwargs)


    def _fill_entity(self, entity, fill_value=''):
        """
        Stuffs this object into the entity.
        Overloaded so that it will do it intelligently, that is removing
        fields set to pythonic None from the entity and handling the wildcard fields
        """

        for attr, attr_value in self.__class__.__dict__.iteritems():
            if isinstance(attr_value, Field):
                value = getattr(self, attr, None)
                if value is not None:
                    attr_value.to_api(value, attr, entity, fill_value)
        for attr, attr_value in self.__dict__.iteritems():
            if attr_value is not None:
                for wildcard_field in self.wildcard_fields.itervalues():
                    if wildcard_field.pattern.match(attr):
                        wildcard_field.field_class.to_api(attr_value, attr, entity, fill_value)
                        break

    def set_entity_fields(self, entity):
        """
        Fill the values of the model from the data given to us by the get entity call
        Also parse the wildcard fields and cache parse time fields
        """
        for (attr, field) in self.model_fields.iteritems():
            setattr(self, attr, field.from_apidata(entity, attr))

        #Parse any wildcard field values
        parsed_values = {}
        for field_name in self.wildcard_fields.keys():
            parsed_values[field_name] = {}
        for entity_attr in entity.keys():
            for field_name, wildcard_field in self.wildcard_fields.iteritems():
                if wildcard_field.pattern.match(entity_attr):
                    from_api_val = wildcard_field.field_class.from_apidata(entity, entity_attr)
                    setattr(self, entity_attr, from_api_val)
                    self.model_fields[entity_attr] = wildcard_field.field_class
                    parsed_values[field_name][entity_attr] = from_api_val
                    break
        #Save as an instance property in case it is needed, note this is parse time only values
        self.parsed_wildcard_fields = parsed_values
        return True

    def delete(self, raise_exceptions=True):
        """Delete a matching record"""

        if not self.id:
            return False
        elif self.entity.hostPath is not None:
            path = self.entity.hostPath + self.id
        elif self.host_path is not None:
            path = self.host_path.rstrip("/") + self.id
        else:
            path = self.id

        response, content = splunk.rest.simpleRequest(path, method='DELETE', sessionKey=self.sessionKey, raiseAllErrors=raise_exceptions)
        del content
        if response.status == 200:
            self.id = None
            return True

        return False

    def passive_delete(self):
        """
        Delete a matching record while supressing exceptions.

        returns True if successful, returns False if something bad happened.
        """
        try:
            retval = self.delete(raise_exceptions=False)
        except Exception:
            retval = False
        return retval

    @classmethod
    def from_name(cls, name, app="search", owner="nobody", host_path=None, session_key=None):
        """
        This method can be thought of as an alternate constructor where you get
        a specific single entity based on the name and app. You can think of the
        syntax as "get me entity with name==name from app==app, under the ownership
        of user==owner" It also can work with remote hosts if you provide a
        host_path and a session_key else it will use defaults
        args:
            name - the name (stanza name) of the entity to get
            app - the app namespace in which to get the entity
            owner - the owner of the entity (splunk user)
            host_path - the path to the host (splunk manager path, e.g. https://localhost:8089)
            session_key - the session_key to use in making the request

        RETURNS the populated model if it exists, False otherwise.
        """
        if name is None:
            raise TypeError("When getting a specific entity for the model, the name of that specific entity is required")
        entity_id = "/servicesNS/" + owner + "/" + app + "/" + cls.resource + "/" + urllib.quote_plus(name)

        try:
            model = SOLNRESTManager(cls, host_path=host_path, sessionKey=session_key).get(entity_id, host_path=host_path)
        except ResourceNotFound:
            model = False
        return model

    def get_id(self):
        """
        This method gets the id if it exists else it builds it and returns it with the current model's state
        """
        if self.id is not None:
            return self.id
        else:
            return buildEntityEndpoint(self.resource, self.name, self.namespace, self.owner, hostPath=self.host_path)

    def from_self(self):
        """
        This method is essentially a wrapper around self.from_name. The goal is to provide
        a refreshed version of this entity that reflects current changes, note that this
        does not refresh the entity in place but rather return a new fresh copy from REST.
        Note this assumes that the self.name property is correct, that is not always the case
        in more complex named models that are constructed new.

        RETURNS the current version of this asset
        """
        return self.from_name(self.name, self.namespace, self.owner, self.host_path, self.sessionKey)

#===============================================================================
# CORE MODELS - Password Storage
#===============================================================================
class SplunkStoredCredential(SOLNAppObjModel):
    '''
    Class for managing secure credential storage.
    Note this class is duplicated in SA-Utils, but this version
    has the fixes for SPL-61482.
    '''

    # Requires Splunk 4.3 or higher.
    resource = 'storage/passwords'

    clear_password = Field()
    encr_password = Field()
    username = Field()
    password = Field()
    realm = Field()

    @staticmethod
    def get_password(realm, user, app="SA-Hydra", session_key=None, host_path=None):
        """
        This method pulls the clear password from storage/passwords for a
        particular realm and user.
        args:
            realm - the realm associated with the stored credential
            user - the user name associated with the stored credential
            app - the app namespace to get the password from
            host_path - the splunk machine to get the credential from
            session_key - the session key to use when talking to splunkd

        RETURNS the clear string of the password, None if not found
        """
        #note we are relying on splunk's internal automagical session_key storage if session_key is None
        cred = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(realm, user), app=app, owner="nobody", host_path=host_path, session_key=session_key)
        if not cred:
            return None
        else:
            return cred.clear_password

    @staticmethod
    def _escapeCredentialString(s):
        '''
        Splunk secure credential storage actually requires a custom style of escaped
        string where all the :'s are escaped by a single \. Oh but don't escape the
        control : in the stanza name, fun right?
        args:
            s - the string to escape

        RETURNS the escaped string
        '''
        return s.replace(":","\\:")

    @staticmethod
    def build_name(realm=None, user=None):
        '''
        The name of a credential is "realm:user:". Yes you need the trailing colon.
        This will create it for you either from passed things.
        args:
            realm - the realm prop for the credential
            user - the user prop for the credential
        '''
        if realm is None:
            realm = ''
        if user is None:
            user = ''
        return SplunkStoredCredential._escapeCredentialString(realm) + ":" + SplunkStoredCredential._escapeCredentialString(user) + ":"

    @classmethod
    def from_name(cls, name, app="search", owner="nobody", host_path=None, session_key=None):
        """
        This method can be thought of as an alternate constructor where you get
        a specific single entity based on the name and app. You can think of the
        syntax as "get me entity with name==name from app==app, under the ownership
        of user==owner" It also can work with remote hosts if you provide a
        host_path and a session_key else it will use defaults
        args:
            name - the name (stanza name) of the entity to get
            app - the app namespace in which to get the entity
            owner - the owner of the entity (splunk user)
            host_path - the path to the host (splunk manager path, e.g. https://localhost:8089)
            session_key - the session_key to use in making the request

        RETURNS the populated model if it exists, False otherwise.
        """
        if name is None:
            raise TypeError("When getting a specific entity for the model, the name of that specific entity is required")
        #In this name we will want to replace the slashes, but only if they don't escape a slash already
        #The reason we do this is because the stored credentials on the splunk side will escape single slashes
        name = re.sub(r'\\([^:])',r'\\\\\1',name)
        entity_id = "/servicesNS/" + owner + "/" + app + "/" + cls.resource + "/" + urllib.quote_plus(name)
        try:
            model = SOLNRESTManager(cls, host_path=host_path, sessionKey=session_key).get(entity_id, host_path=host_path)
        except ResourceNotFound:
            model = False
        return model


    def save(self):
        '''
        Overload of the base model save.
        The POST method for this endpoint requires the syntax realm:user
        be appended to the URI, necessitating the use of custom _put_args.

        Also note that you cannot edit the realm nor the username, just the password
        You'll get a resource not found error, which will crash this puppy.
        '''
        if self.realm is None:
            raise ValueError("Must explicitly set realm of SplunkStoredCredential model before calling save(), if you wish for no realm set to empty string")
        if self.username is None:
            raise ValueError("Must explicitly set username of SplunkStoredCredential model before calling save(), if you wish for no username set to empty string")
        existing_instance = SplunkStoredCredential.from_name(SplunkStoredCredential.build_name(self.realm,self.username), self.namespace, self.owner, session_key=self.sessionKey,host_path=self.host_path)
        if not self.id and not existing_instance:
            return self.create()

        if not self.entity and not existing_instance:
            self.id = None
            return self.create()

        if existing_instance:
            existing_instance.password = self.password
            return existing_instance._edit_cred_password()
        else:
            raise TypeError("Somehow this SplunkStoredCredential instance got into a state where it thinks it exists but it doesn't.")

    def _edit_cred_password(self):
        """
        Edit this existent instance of a credential's password
        """
        self._fill_entity(self.entity)
        # ensure that non-mutable fields are not passed back to splunkd
        for field in self.model_fields:
            if not self.model_fields[field].get_is_mutable():
                #logger.debug('removing non-mutable field: %s' % field)
                try:
                    del self.entity.properties[self.model_fields[field].get_api_name(field)]
                except KeyError:
                    pass
        postargs = {'password': self.password}
        cred_id = self.build_id(self.build_name(self.realm, self.username.replace("\\","\\\\")), self.namespace, self.owner)

        if self.host_path is not None:
            cred_id = self.host_path + cred_id

        self.manager()._put_args(cred_id, postargs, sessionKey=self.sessionKey)
        return True

    def create(self):
        """
        We need to overload the create method so that when we create a new entity we do not pass the username field, by default
        this will fail because the REST spec for create does not include username, passwords are special.
        """
        if self.metadata.sharing != 'user':
            self.owner = 'nobody'

        if self.id:
            return False

        if not self.entity:
            self.entity = self.manager()._get_new_entity(self.namespace, self.owner,
                host_path=self.host_path,
                sessionKey=self.sessionKey)

        self._fill_entity(self.entity, None)

        self.entity['name'] = self.name

        messages = []
        new_endpoint = splunk.entity.buildEndpoint(self.resource, namespace=self.namespace,
            owner=self.owner, hostPath=self.host_path)

        #Edit the entity properties to remove the username
        del self.entity.properties["username"]

        newEntity = self.manager()._put_entity(new_endpoint, self.entity, messages, sessionKey=self.sessionKey)

        if not newEntity:
            return False
        else:
            self.entity = newEntity
            self.from_entity(self.entity)
            self.metadata.from_entity(self.entity)
            return True

########################################################################
# EXAMPLE IMPLEMENTATION - COLLECTION MODEL
########################################################################

class HydraCollectionStanza(SOLNAppObjModel):
    '''
    Provides object mapping for the example hydra collection stanzas
    The conf file is used to determine what jobs are to be done to what hosts in the prototype this amounts to printing a message.
    Field Meanings:
        target - The target resources on which to apply the job, typically a remote host, this is a comma delimited list of targets
        username - The username to use on all targets for auth purposes
        realm - the realm if using realms based credential storage
        task - The types of the jobs to be executed, which matches the capability of a worker that can execute it, this is a comma delimited list of tasks
        message - This is a message to print out
        big_job_interval - The collection interval for the particular task
        medium_job_interval - ibidem
        small_job_interval - ibidem
    '''

    resource = 'configs/conf-hydra_collection'

    use_model_as_spec = True

    target = CSVField()
    username = Field()
    realm = Field()
    task = CSVField()
    message = Field()
    big_job_interval = IntField()
    medium_job_interval = IntField()
    small_job_interval = IntField()

#===============================================================================
# EXAMPLE/DEFAULT IMPLEMENTATION - CACHE MODEL
#===============================================================================

class HydraCacheStanza(SOLNAppObjModel):
    '''
    Provides object mapping for the hydra cache stanzas
    This can be used as an example when making your own cache models
    The conf file should NEVER be managed manually, it is a datastore for the shared session objects
    Field Meanings:
        string_data - This is a string representing some string data
        python_data - This is the serialized python object representing some serialized python data
        worker - This is a pointer to the worker that is currently editing the cache,
            workers will use this field to 'lock' this session to avoid collisions
    '''

    resource = 'configs/conf-hydra_cache'

    use_model_as_spec = True

    string_data = Field()
    python_data = PythonObjectField()
    worker = Field()
    last_lock_time = ISODateTimeField()



