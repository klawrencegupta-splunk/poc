
import logging
import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page, set_cache_level
from splunk.appserver.mrsparkle.lib.routes import route
from Splunk_TA_f5_bigip.splunklib.client import Service

from splunk import getDefault


logger = logging.getLogger('splunk')
logger.setLevel(logging.ERROR)

class F5IndexHandler(controllers.BaseController):
    @staticmethod
    def get_session_key():
        session_key = cherrypy.session.get('sessionKey')

        cherrypy.session.release_lock()

        return session_key

    # Return including default one
    @route('=indexes')
    @expose_page(must_login=True, methods=['GET'])
    def get_all_indexes(self, **params):
        host = getDefault('host')
        port = getDefault('port')
        protocol = getDefault('protocol')
        token = F5IndexHandler.get_session_key()
        service = Service(token=token, host=host, port=port, scheme=protocol)
        indexes = [{"name": "default"}]
        for index in service.indexes:
            if index['content']['disabled'] == '0' and index['content']['isInternal'] == '0':
                indexes.append({"name": index['name']})
        return self.render_json(indexes)

