
import logging
import cherrypy
import json
import splunk.appserver.mrsparkle.controllers as controllers

from splunk.appserver.mrsparkle.lib.decorators import expose_page, set_cache_level
from splunk.appserver.mrsparkle.lib.routes import route

from Splunk_TA_f5_bigip.Modules.F5Tasks import F5TasksManager, TaskData

logger = logging.getLogger('splunk')
logger.setLevel(logging.ERROR)


class F5TaskHandler(controllers.BaseController):
    @staticmethod
    def get_session_key():
        session_key = cherrypy.session.get('sessionKey')
        cherrypy.session.release_lock()

        return session_key

    def get_all(self, **params):
        session_key = self.get_session_key()
        tasks = F5TasksManager(session_key).all()

        result = []
        for task in tasks:
            result.append(task.to_dict())

        return self.render_json(result)

    def get_one(self, cid, **params):
        task_manager = F5TasksManager(self.get_session_key())
        task = task_manager.get(TaskData().from_id(cid))

        return self.render_json(task.to_dict())

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
        task_data = TaskData().from_params(params)
        task_manager = F5TasksManager(self.get_session_key())
        task = task_manager.create(task_data)
        if not task:
            self.error_in_managing(status=409,
                                   message='Task creating failed. There is a task of the same name.')
        elif task.errors:
            self.error_in_managing(status=409, message='Task creating failed.', errors=task.errors)
        else:
            return self.render_json(task.to_dict())

    def update(self, cid, **params):
        task_data = TaskData().from_params(params).from_id(cid)
        task_manager = F5TasksManager(self.get_session_key())
        task = task_manager.update(task_data)

        if task.errors:
            self.error_in_managing(status=409, message='Task updating failed.', errors=task.errors)
        else:
            return self.render_json(task.to_dict())

    def delete(self, cid, **params):
        task_data = TaskData().from_id(cid)
        task_manager = F5TasksManager(self.get_session_key())
        task = task_manager.delete(task_data)

        if not task:
            self.render_json({'message': 'There is no task of this name.'})
        elif task.errors:
            self.error_in_managing(status=409, message='Task deleting failed.', errors=task.errors)
        else:
            return self.render_json({'status': 200, 'message': 'Task successfully deleted.'})


    @route('=tasks')
    @expose_page(must_login=True, methods=['GET', 'POST'])
    def handle_all(self, **params):
        method = cherrypy.request.method.upper()

        if method == "GET":
            return self.get_all(**params)
        elif method == "POST":
            cl = cherrypy.request.headers['Content-Length']
            rawbody = cherrypy.request.body.read(int(cl))
            task = json.loads(rawbody)
            # return str(body)
            return self.create(**task)

    @route('=tasks/:cid')
    @expose_page(must_login=True, methods=['GET', 'PUT', 'DELETE'])
    def handle_one(self, cid, **params):
        method = cherrypy.request.method.upper()

        if method == "GET":
            return self.get_one(cid, **params)
        elif method == "PUT":
            cl = cherrypy.request.headers['Content-Length']
            rawbody = cherrypy.request.body.read(int(cl))
            task = json.loads(rawbody)
            return self.update(cid, **task)
        elif method == "DELETE":
            return self.delete(cid, **params)

