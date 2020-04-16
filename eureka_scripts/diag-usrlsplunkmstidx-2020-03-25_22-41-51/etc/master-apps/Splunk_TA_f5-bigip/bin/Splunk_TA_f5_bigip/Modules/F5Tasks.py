'''
Copyright (C) 2005 - 2013 Splunk Inc. All Rights Reserved.
'''
import splunk
from splunk import AuthenticationFailed, ResourceNotFound
from splunk.models.base import SplunkAppObjModel
from splunk.models.field import Field, BoolField, IntField
import splunk.rest
import logging

from models import SOLNAppObjModel
from Splunk_TA_f5_bigip.ta_util.ta_accesskeys import APPNAME
from Splunk_TA_f5_bigip.ta_util.ta_accesskeys import TaAccessKeyManager

logger = logging.getLogger('splunk')
logger.setLevel(logging.ERROR)
DEFAULT_OWNER_USER = "nobody"


class TaskData:
    def __init__(self):
        self.id = ""
        self.name = ""
        self.description = ""
        self.appName = ""
        self.servers = ""
        self.templates = ""
        self.interval = ""
        self.index = ""
        self.sourcetype = ""
        self.disabled = ""

    def from_id(self, cid):
        self.id = cid
        self.appName = self.id.split(':')[0]
        self.name = self.id.split(':')[1]

        return self

    def from_params(self, params):
        self.name = params.get("name", "")
        self.description = params.get("description", "")
        self.appName = params.get("appName", APPNAME)
        self.servers = params.get("servers", "")
        self.templates = params.get("templates", "")
        self.interval = params.get("interval", "")
        self.index = params.get("index", "")
        self.sourcetype = params.get("sourcetype", "")
        self.disabled = params.get("disabled", "")

        self.id = self.appName + ":" + self.name

        return self


class F5TaskModel(SOLNAppObjModel):
    resource = 'configs/conf-f5_bigip_tasks'

    use_model_as_spec = True

    name = Field()
    description = Field(default_value="")
    servers = Field(default_value="")
    templates = Field(default_value="")
    index = Field(default_value="default")
    sourcetype = Field(default_value="f5_bigip")
    interval = IntField(default_value=1000)
    disabled = BoolField(default_value=1)

    def __str__(self):
        ret = super(F5TaskModel, self).__str__()

        ret += ", description: " + str(self.description) + \
               ", servers:" + str(self.servers) + \
               ", templates:" + str(self.templates) + \
               ", index:" + str(self.index) + \
               ", sourcetype:" + str(self.sourcetype) + \
               ", interval:" + str(self.interval) + \
               ", disabled:" + str(self.disabled)
        return ret

    def from_data(self, task_data):
        self.name = task_data.name
        self.description = task_data.description
        self.namespace = task_data.appName
        self.servers = task_data.servers
        self.templates = task_data.templates
        self.index = task_data.index
        self.sourcetype = task_data.sourcetype
        self.interval = task_data.interval
        self.disabled = task_data.disabled

        return self

    # for output purpose
    def to_dict(self):
        ret = dict()
        ret["name"] = self.name
        ret["description"] = self.description
        ret["appName"] = self.namespace
        ret["servers"] = self.servers
        ret["templates"] = self.templates
        ret["index"] = self.index
        ret["sourcetype"] = self.sourcetype
        ret["interval"] = self.interval
        ret["disabled"] = self.disabled

        ret["id"] = self.namespace + ":" + self.name
        try:
            ret["_removable"] = self.metadata.can_remove
        except:
            ret["_removable"] = True

        for key in ret:
            if ret[key] is None:
                ret[key] = ''
        return ret

    def get_metadata(self):
        return {
            'index': self.index,
            'sourcetype': self.sourcetype,
            'global_interval': self.interval,
        }

    def get_server_keys(self):
        return [key.strip() for key in str(self.servers).split('|')] if self.servers else []

    def get_template_keys(self):
        return [key.strip() for key in str(self.templates).split('|')] if self.templates else []

    def get_hash(self):
        return hash((self.name, self.index, self.sourcetype, self.interval))


class F5TasksManager(object):
    def __init__(self, sessionKey=None):
        if sessionKey is None:
            raise AuthenticationFailed('A session key was not provided.')
        self._sessionKey = sessionKey

    def create(self, task_data, owner=DEFAULT_OWNER_USER):
        if self.get(task_data, owner=owner):
            return None
        model = F5TaskModel(task_data.appName, owner, task_data.name, sessionKey=self._sessionKey)
        model.from_data(task_data)
        model.create()
        return model


    def get(self, task_data, owner=DEFAULT_OWNER_USER):
        server_id = F5TaskModel.build_id(task_data.name, task_data.appName, owner)
        try:
            model = F5TaskModel.get(server_id, self._sessionKey)
            if model.namespace != task_data.appName:
                raise Exception()
        except:
            return None
        return model

    def update(self, task_data, owner=DEFAULT_OWNER_USER):
        model = self.get(task_data, owner=owner)
        if not model:
            return self.create(task_data, owner=owner)
        model.from_data(task_data)
        model.name = ''
        model.passive_save()
        model.name = task_data.name
        return model


    def delete(self, task_data, owner=DEFAULT_OWNER_USER):
        model = self.get(task_data, owner=owner)
        if model is None:
            return None
        model.delete()
        return model

    def all(self):
        class AccessTaskIterator(object):
            def __init__(self, session_key):
                self._sessionKey = session_key
                self.tasks = F5TaskModel.all(sessionKey=self._sessionKey, namespace='-')

            def __iter__(self):
                for task in self.tasks:
                    # load account for the task
                    yield task

        return AccessTaskIterator(self._sessionKey)

    def reload(self):
        splunk.rest.simpleRequest(F5TaskModel.build_id(None, None, None) + "/_reload", sessionKey=self._sessionKey)

    def get_by_name(self, name, appName='-', owner='-'):
        server_id = F5TaskModel.build_id(name, appName, owner)
        try:
            model = F5TaskModel.get(server_id, self._sessionKey)
            if appName != '-' and model.namespace != appName:
                raise Exception()
        except:
            return None
        return model