'''
Copyright (C) 2005 - 2013 Splunk Inc. All Rights Reserved.
'''
import splunk
from splunk import AuthenticationFailed, ResourceNotFound
from splunk.models.base import SplunkAppObjModel
from splunk.models.field import Field, BoolField
import splunk.rest
import logging
import xml.etree.ElementTree as ET

from models import SOLNAppObjModel
from Splunk_TA_f5_bigip.ta_util.ta_accesskeys import APPNAME
from Splunk_TA_f5_bigip.ta_util.ta_accesskeys import TaAccessKeyManager

logger = logging.getLogger('splunk')
logger.setLevel(logging.ERROR)
DEFAULT_OWNER_USER = "nobody"
CONFIDENTIAL_PREFIX = "_%s_account_" % APPNAME

'''
host
f5_bigip_port
protocol
lookupPath
stubSource
encodedStub
pid" type="xs:integer">
pidFile
pidCommand
interval" type="xs:integer">
'''


class ServerData:
    def __init__(self):
        self.id = ""
        self.name = ""
        self.description = ""
        self.appName = ""
        self.f5_bigip_url = ""
        self.f5_bigip_partitions = ""
        self.account_name = ""
        self.account_password = ""
        # add fields
        self.host=''
        self.f5_bigip_port=''
        self.protocol=''
        self.lookupPath=''
        self.stubSource=''
        self.encodedStub=''
        self.pid=''
        self.pidFile=''
        self.pidCommand=''
        self.interval=''

    def from_id(self, cid):
        self.id = cid
        self.appName = self.id.split(':')[0]
        self.name = self.id.split(':')[1]

        return self

    def from_params(self, params):
        self.name = params.get("name", "")
        self.description = params.get("description", "")
        self.appName = params.get("appName", APPNAME)
        self.f5_bigip_url = params.get("f5_bigip_url", "")
        self.f5_bigip_partitions = params.get("f5_bigip_partitions", "")
        self.account_name = params.get("account_name", "")
        self.account_password = params.get("account_password", "")

        # id is appName:name
        self.id = self.appName + ":" + self.name

        # add fields
        self.host= params.get("host", "")
        self.f5_bigip_port= params.get("f5_bigip_port", "")
        self.protocol= params.get("protocol", "")
        self.lookupPath= params.get("lookupPath", "")
        if self.lookupPath and self.lookupPath[0]!='/':
            self.lookupPath='/'+self.lookupPath
        self.stubSource= params.get("stubSource", "")
        self.encodedStub= params.get("encodedStub", "")
        self.pid= params.get("pid", "")
        self.pidFile= params.get("pidFile", "")
        self.pidCommand= params.get("pidCommand", "")
        self.interval= params.get("interval", "")

        return self



class F5ServerModel(SOLNAppObjModel):
    # Requires Splunk 4.3 or higher.
    resource = 'configs/conf-f5_bigip_servers'

    use_model_as_spec = True

    name = Field()
    description = Field(default_value="")
    f5_bigip_url = Field(default_value="")
    f5_bigip_partitions = Field(default_value="")
    has_account = BoolField(default_value=0)
    account_name = ""
    account_password = ""
    # add fields
    host=Field(default_value="")
    f5_bigip_port=Field(default_value="")
    protocol=Field(default_value="")
    lookupPath=Field(default_value="")
    stubSource=Field(default_value="")
    encodedStub=Field(default_value="")
    pid=Field(default_value="")
    pidFile=Field(default_value="")
    pidCommand=Field(default_value="")
    interval=Field(default_value="")


    def __str__(self):
        ret = super(F5ServerModel, self).__str__()

        ret += ", description: " + self.description + \
               ", f5_bigip_url:" + self.f5_bigip_url + \
               ", f5_bigip_partitions:" + self.f5_bigip_partitions + \
               ", has account:" + str(self.has_account) + \
               ", account_name:" + self.account_name + \
               ", account_password:" + self.account_password
        return ret

    def from_data(self, server_data):
        self.name = server_data.name
        self.description = server_data.description
        self.namespace = server_data.appName
        self.f5_bigip_url = server_data.f5_bigip_url
        self.f5_bigip_partitions = server_data.f5_bigip_partitions
        self.account_name = server_data.account_name
        self.account_password = server_data.account_password

        # update has account
        self.has_account = 1 if self.account_name else 0

        # add fields
        self.host= server_data.host
        self.f5_bigip_port= server_data.f5_bigip_port
        self.protocol= server_data.protocol
        self.lookupPath= server_data.lookupPath
        self.stubSource= server_data.stubSource
        self.encodedStub= server_data.encodedStub
        self.pid= server_data.pid
        self.pidFile= server_data.pidFile
        self.pidCommand= server_data.pidCommand
        self.interval= server_data.interval

        return self

    # for output purpose
    def to_dict(self):
        ret = dict()
        ret["name"] = self.name
        ret["description"] = self.description
        ret["appName"] = self.namespace
        ret["f5_bigip_url"] = self.f5_bigip_url
        ret["f5_bigip_partitions"] = self.f5_bigip_partitions
        ret["has_account"] = 1 if self.account_name else 0
        ret["account_name"] = self.account_name
        ret["account_password"] = self.account_password
        ret["id"] = self.namespace + ":" + self.name
        try:
            ret["_removable"]=self.metadata.can_remove
        except:
            ret["_removable"]=True


        # add fields
        ret["host"]=self.host
        ret["f5_bigip_port"]=self.f5_bigip_port
        ret["protocol"]=self.protocol
        ret["lookupPath"]=self.lookupPath
        ret["stubSource"]=self.stubSource
        ret["encodedStub"]=self.encodedStub
        ret["pid"]=self.pid
        ret["pidFile"]=self.pidFile
        ret["pidCommand"]=self.pidCommand
        ret["interval"]=self.interval

        for key in ret:
            if ret[key] is None:
                ret[key] = ''
        return ret


    def to_xml(self):
        server_dict=self.to_dict()
        # rename fields
        server_dict['jvmDescription']=server_dict['description']
        server_dict['f5bigipServiceURL']=server_dict['f5_bigip_url']
        server_dict['f5_bigip_partitions']=server_dict['f5_bigip_partitions']
        if server_dict['has_account']!=0:
            server_dict['f5bigipaccount']=self.confidential_name
        # delete fields
        del server_dict['name']
        del server_dict['description']
        del server_dict["appName"]
        del server_dict['f5_bigip_url']
        del server_dict['f5_bigip_partitions']
        del server_dict['has_account']
        del server_dict['account_name']
        del server_dict['account_password']
        del server_dict['id']
        del server_dict['_removable']

        server_et = ET.Element('f5bigipserver')
        for key in server_dict:
            if server_dict[key]:
                server_et.set(key,server_dict[key])

        out = ET.tostring(server_et, encoding='UTF-8')
        out = out[out.find('\n') + 1:]
        return out

    @property
    def confidential_name(self):
        return '%s#%s#%s'%(CONFIDENTIAL_PREFIX, self.namespace, self.name)

    def load_account(self, session_key):
        if self.has_account:
            acc = TaAccessKeyManager(session_key).get_accesskey(name=self.confidential_name)
            self.account_name, self.account_password = acc.key_id, acc.secret_key

        return self

    def save_account(self, session_key, delete_if_empty=True):
        if self.account_name:
            TaAccessKeyManager(session_key).set_accesskey(
                self.account_name, self.account_password, self.confidential_name)
        elif delete_if_empty:
            # try delete it if it's empty
            TaAccessKeyManager(session_key).delete_accesskey(self.confidential_name)

        return self

    def delete_account(self, session_key):
        TaAccessKeyManager(session_key).delete_accesskey(self.confidential_name)


class F5ServersManager(object):
    
    def __init__(self, sessionKey=None):
        if sessionKey is None:
            raise AuthenticationFailed('A session key was not provided.')
        self._sessionKey = sessionKey

    def create(self, server_data, owner=DEFAULT_OWNER_USER):
        if self.get(server_data, owner=owner):
            return None
        model = F5ServerModel(server_data.appName, owner, server_data.name, sessionKey=self._sessionKey)
        model.from_data(server_data).save_account(self._sessionKey)
        if model.create():
            return model.load_account(self._sessionKey)
        return model

    def get(self, server_data, owner=DEFAULT_OWNER_USER):
        server_id = F5ServerModel.build_id(server_data.name, server_data.appName, owner)
        try:
            model = F5ServerModel.get(server_id, self._sessionKey)
            if model.namespace!=server_data.appName:
                raise Exception()
        except:
            return None
        return model.load_account(self._sessionKey)

    def update(self, server_data, owner=DEFAULT_OWNER_USER):
        model = self.get(server_data, owner=owner)
        if not model:
            return self.create(server_data, owner=owner)
        model.from_data(server_data).save_account(self._sessionKey)
        model.name=''
        model.passive_save()
        model.name=server_data.name
        return model

    def delete(self, server_data, owner=DEFAULT_OWNER_USER):
        model = self.get(server_data, owner=owner)
        if model is None:
            return None
        model.delete_account(self._sessionKey)
        model.delete()
        return model

    def all(self):
        class AccessServerIterator(object):
            def __init__(self, session_key):
                self._sessionKey = session_key
                self.servers = F5ServerModel.all(sessionKey=self._sessionKey, namespace='-')

            def __iter__(self):
                for server in self.servers:
                    # load account for the server
                    yield server.load_account(self._sessionKey)

        return AccessServerIterator(self._sessionKey)

    def reload(self):
        splunk.rest.simpleRequest(F5ServerModel.build_id(None, None, None) + "/_reload", sessionKey=self._sessionKey)