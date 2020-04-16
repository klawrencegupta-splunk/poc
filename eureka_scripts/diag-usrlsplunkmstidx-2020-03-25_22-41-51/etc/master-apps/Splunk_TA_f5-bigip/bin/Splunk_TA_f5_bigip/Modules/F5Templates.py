'''
Copyright (C) 2005 - 2013 Splunk Inc. All Rights Reserved.
'''
import splunk
from splunk import AuthenticationFailed, ResourceNotFound
from splunk.models.base import SplunkAppObjModel
from splunk.models.field import Field, BoolField
import splunk.rest
import logging

from models import SOLNAppObjModel
from Splunk_TA_f5_bigip.ta_util.ta_accesskeys import APPNAME
import base64

logger = logging.getLogger('splunk')
logger.setLevel(logging.ERROR)
DEFAULT_OWNER_USER = "nobody"


class TemplateData:
    def __init__(self):
        self.id = ""
        self.name = ""
        self.description = ""
        self.appName = ""
        self.content = ""

    def from_id(self, cid):
        self.id = cid
        self.appName = self.id.split(':')[0]
        self.name = self.id.split(':')[1]

        return self

    def from_params(self, params):
        self.name = params.get("name", "")
        self.description = params.get("description", "")
        self.appName = params.get("appName", APPNAME)
        self.content = params.get("content", "")

        # id is appName:name
        self.id = self.appName + ":" + self.name

        return self



class F5TemplateModel(SOLNAppObjModel):
    resource = 'configs/conf-f5_bigip_templates'

    use_model_as_spec = True

    name = Field()
    description = Field(default_value="")
    content = Field(default_value="")

    def __str__(self):
        ret = super(F5TemplateModel, self).__str__()

        ret += ", name: " + self.name + \
               ", description:" + self.description + \
               ", appName:" + str(self.namespace) + \
               ", content:" + self.content
        return ret

    def from_data(self, template_data):
        self.name = template_data.name
        self.description = template_data.description
        self.namespace = template_data.appName
        self.content = template_data.content

        return self

    # for output purpose
    def to_dict(self):
        ret = dict()
        ret["name"] = self.name
        ret["description"] = self.description
        ret["appName"] = self.namespace
        ret["content"] = self.content

        # note: id
        ret["id"] = self.namespace + ":" + self.name
        try:
            ret["_removable"]=self.metadata.can_remove
        except:
            ret["_removable"]=True


        for key in ret:
            if ret[key] is None:
                ret[key] = ''
        return ret

    def encode_content(self):
        self.content = self.encode(self.content)

        return self

    def decode_content(self):
        # encode the content into base64
        self.content = self.decode(self.content)

        return self

    @staticmethod
    def decode(content):
        return base64.urlsafe_b64decode(content)

    @staticmethod
    def encode(content):
        return base64.urlsafe_b64encode(content)

class F5TemplatesManager(object):
    
    def __init__(self, sessionKey=None):
        if sessionKey is None:
            raise AuthenticationFailed('A session key was not provided.')
        self._sessionKey = sessionKey

    def create(self, template_data, owner=DEFAULT_OWNER_USER):
        if self.get(template_data, owner=owner):
            return None
        model = F5TemplateModel(template_data.appName, owner, template_data.name, sessionKey=self._sessionKey)
        model.from_data(template_data).encode_content()
        if model.create():
            return model.decode_content()
        return model

    def get(self, template_data, owner=DEFAULT_OWNER_USER):
        template_id = F5TemplateModel.build_id(template_data.name, template_data.appName, owner)
        try:
            model = F5TemplateModel.get(template_id, self._sessionKey)
            if model.namespace!=template_data.appName:
                raise Exception()
        except:
            return None
        return model.decode_content()

    def update(self, template_data, owner=DEFAULT_OWNER_USER):
        model = self.get(template_data, owner=owner)
        if not model:
            return self.create(template_data, owner=owner)
        model.from_data(template_data).encode_content()
        model.name=''
        model.passive_save()
        model.name=template_data.name
        return model.decode_content()

    def delete(self, template_data, owner=DEFAULT_OWNER_USER):
        model = self.get(template_data, owner=owner)
        if model is None:
            return None
        model.delete()
        return model

    def all(self):
        class AccessServerIterator(object):
            def __init__(self, session_key):
                self._sessionKey = session_key
                self.servers = F5TemplateModel.all(sessionKey=self._sessionKey, namespace='-')

            def __iter__(self):
                for server in self.servers:
                    yield server.decode_content()

        return AccessServerIterator(self._sessionKey)

    def reload(self):
        splunk.rest.simpleRequest(F5TemplateModel.build_id(None, None, None) + "/_reload", sessionKey=self._sessionKey)
