
import logging
import cherrypy
import json
import splunk.appserver.mrsparkle.controllers as controllers

from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route

from Splunk_TA_f5_bigip.Modules.F5Servers import F5ServersManager, ServerData

logger = logging.getLogger('splunk')
logger.setLevel(logging.ERROR)


class F5ServerHandler(controllers.BaseController):
    @staticmethod
    def get_session_key():
        session_key = cherrypy.session.get('sessionKey')
        cherrypy.session.release_lock()

        return session_key

    def get_all(self, **params):
        session_key = self.get_session_key()
        servers = F5ServersManager(session_key).all()

        result = []
        for server in servers:
            s = server.to_dict()
            del s['account_password']
            result.append(s)

        return self.render_json(result)

    def get_one(self, cid, **params):
        server_manager = F5ServersManager(self.get_session_key())
        server = server_manager.get(ServerData().from_id(cid))

        return self.render_json(server.to_dict())

    @staticmethod
    def validate_params(must_params, opt_params, **params):
        pass

    def error_in_managing(self, **param):
        status = 409
        message = 'unknown error'
        if 'status' in param:
            status = int(param['status'])
        if 'message' in param:
            message = str(param['message'])
        if 'errors' in param:
            message = str(param['errors'])
        raise cherrypy.HTTPError(status, message)

    def create(self, **params):
        server_data = ServerData().from_params(params)
        server_manager = F5ServersManager(self.get_session_key())
        server = server_manager.create(server_data)
        if not server:
            self.error_in_managing(status=409,
                                   message='Server creating failed. There is a server of the same name.')
        elif server.errors:
            self.error_in_managing(status=409, message='Server creating failed.', errors=server.errors)
        else:
            return self.render_json(server.to_dict())


    def update(self, cid, **params):
        server_data = ServerData().from_params(params).from_id(cid)
        server_manager = F5ServersManager(self.get_session_key())

        previous_server = server_manager.get(ServerData().from_id(cid))

        if server_data.account_name == previous_server.account_name:
            if server_data.account_password == '':
                server_data.account_password = previous_server.account_password

        server = server_manager.update(server_data)

        if server.errors:
            self.error_in_managing(status=409, message='Server updating failed.', errors=server.errors)
        else:
            return self.render_json(server.to_dict())


    def delete(self, cid, **params):
        server_data = ServerData().from_id(cid)
        server_manager = F5ServersManager(self.get_session_key())
        server = server_manager.delete(server_data)

        if not server:
            self.render_json({'message': 'There is no server of this name.'})
        elif server.errors:
            self.error_in_managing(status=409, message='Server deleting failed.', errors=server.errors)
        else:
            return self.render_json({'status': 200, 'message': 'Server successfully deleted.'})


    @route('=servers')
    @expose_page(must_login=True, methods=['GET', 'POST'])
    def handle_all(self, **params):
        method = cherrypy.request.method.upper()

        if method == "GET":
            return self.get_all(**params)
        elif method == "POST":
            cl = cherrypy.request.headers['Content-Length']
            rawbody = cherrypy.request.body.read(int(cl))
            server = json.loads(rawbody)
            # return str(body)
            return self.create(**server)

    @route('=servers/:cid')
    @expose_page(must_login=True, methods=['GET', 'PUT', 'DELETE'])
    def handle_one(self, cid, **params):
        method = cherrypy.request.method.upper()

        if method == "GET":
            return self.get_one(cid, **params)
        elif method == "PUT":
            cl = cherrypy.request.headers['Content-Length']
            rawbody = cherrypy.request.body.read(int(cl))
            server = json.loads(rawbody)
            return self.update(cid, **server)
        elif method == "DELETE":
            return self.delete(cid, **params)
