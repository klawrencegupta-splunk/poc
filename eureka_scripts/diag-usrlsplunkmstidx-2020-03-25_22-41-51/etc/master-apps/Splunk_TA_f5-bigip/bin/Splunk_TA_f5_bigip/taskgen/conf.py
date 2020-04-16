from splunklib.client import Service, Collection, Entity


class ConfLoader(object):
    def __init__(self, service, conf_name, app_name='-', owner='-', load_metadata=False, filter=None):
        self.service = service
        self.conf_name = conf_name
        self.app_name = app_name
        self.owner = owner
        self.load_metadata = load_metadata
        self.filter=filter

    def conf_path(self):
        return '/services/configs/conf-%s/' % self.conf_name

    def conf_NS_path(self):
        return '/servicesNS/%s/%s/configs/conf-%s/' % (self.owner, self.app_name, self.conf_name)

    def load(self):
        path = self.conf_path()
        if isinstance(self.service, Service):
            self.service.get(path + '_reload')  # Try simpleRequest(url,token) instead if failed
            conf_endpoint = Collection(self.service, path)
            conf = {}
            for stanza in conf_endpoint:
                if self.filter and not self.filter(stanza['name']):
                    continue
                conf[stanza['name']] = stanza['content']
            return conf
        else:
            raise TypeError("service must be a splunklib.client.Service object")

    def loadNS(self):
        path = self.conf_NS_path()
        if isinstance(self.service, Service):
            self.service.get(path + '_reload')  # Try simpleRequest(url,token) instead if failed
            conf_endpoint = Collection(self.service, path)
            conf = {}
            for stanza in conf_endpoint:
                if self.filter and not self.filter(stanza['name']):
                    continue
                app_name=stanza['content']['eai:appName']
                if not app_name in conf:
                    conf[app_name]={}
                conf[app_name][stanza['name']] = stanza['content']
            return conf
        else:
            raise TypeError("service must be a splunklib.client.Service object")