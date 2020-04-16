
import logging
import cherrypy
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page, set_cache_level
from splunk.appserver.mrsparkle.lib.routes import route
from Splunk_TA_f5_bigip.splunklib.client import Service

from splunk import getDefault

logger = logging.getLogger('splunk')
logger.setLevel(logging.ERROR)

class F5AppHandler(controllers.BaseController):
    @staticmethod
    def get_session_key():
        session_key = cherrypy.session.get('sessionKey')

        cherrypy.session.release_lock()

        return session_key

    # Return including default one
    @route('=apps')
    @expose_page(must_login=True, methods=['GET'])
    def get_all_apps(self, **params):
        host = getDefault('host')
        port = getDefault('port')
        protocol = getDefault('protocol')
        token = self.get_session_key()
        service = Service(token=token, host=host, port=port, scheme=protocol)
        apps = []
        for app in service.apps:
            if app['content']['disabled'] == '0' :
                apps.append({"name": app['name']})
        return self.render_json(apps)