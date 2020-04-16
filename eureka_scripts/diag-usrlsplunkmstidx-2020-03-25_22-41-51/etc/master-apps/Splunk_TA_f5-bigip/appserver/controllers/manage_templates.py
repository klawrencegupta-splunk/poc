import logging
import cherrypy
import json
import splunk.appserver.mrsparkle.controllers as controllers

from splunk.appserver.mrsparkle.lib.decorators import expose_page, set_cache_level
from splunk.appserver.mrsparkle.lib.routes import route

from Splunk_TA_f5_bigip.Modules.F5Templates import F5TemplatesManager, TemplateData

logger = logging.getLogger('splunk')
logger.setLevel(logging.ERROR)


class F5TemplatesHandler(controllers.BaseController):
    @staticmethod
    def get_session_key():
        session_key = cherrypy.session.get('sessionKey')
        cherrypy.session.release_lock()

        return session_key

    def get_all(self, **params):
        session_key = self.get_session_key()
        templates = F5TemplatesManager(session_key).all()

        result = []
        for template in templates:
            result.append(template.to_dict())

        return self.render_json(result)

    def get_one(self, cid, **params):
        template_manager = F5TemplatesManager(self.get_session_key())
        template = template_manager.get(TemplateData().from_id(cid))

        return self.render_json(template.to_dict())

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
        # self.validate_params("{'name': '\w+', }", "{'description': ''}", **params)
        #
        template_data = TemplateData().from_params(params)
        template_manager = F5TemplatesManager(self.get_session_key())
        template = template_manager.create(template_data)
        if not template:
            self.error_in_managing(status=409,
                                   message='Template creating failed. There is a template of the same name.')
        elif template.errors:
            self.error_in_managing(status=409, message='Template creating failed.', errors=template.errors)
        else:
            return self.render_json(template.to_dict())

    def update(self, cid, **params):
        template_data = TemplateData().from_params(params).from_id(cid)
        template_manager = F5TemplatesManager(self.get_session_key())
        template = template_manager.update(template_data)
        if template.errors:
            self.error_in_managing(status=409, message='Template updating failed.', errors=template.errors)
        else:
            return self.render_json(template.to_dict())

    def delete(self, cid, **params):
        template_data = TemplateData().from_id(cid)
        template_manager = F5TemplatesManager(self.get_session_key())
        template = template_manager.delete(template_data)
        if not template:
            self.render_json({'message': 'There is no template of this name.'})
        elif template.errors:
            self.error_in_managing(status=409, message='Template deleting failed.', errors=template.errors)
        else:
            return self.render_json({'status': 200, 'message': 'Template successfully deleted.'})

    @route('=templates')
    @expose_page(must_login=True, methods=['GET', 'POST'])
    def handle_all(self, **params):
        method = cherrypy.request.method.upper()

        if method == "GET":
            return self.get_all(**params)
        elif method == "POST":
            cl = cherrypy.request.headers['Content-Length']
            rawbody = cherrypy.request.body.read(int(cl))
            template = json.loads(rawbody)
            return self.create(**template)

    @route('=templates/:cid')
    @expose_page(must_login=True, methods=['GET', 'PUT', 'DELETE'])
    def handle_one(self, cid, **params):
        method = cherrypy.request.method.upper()

        if method == "GET":
            return self.get_one(cid, **params)
        if method == "GET":
            return self.get_one(cid, **params)
        elif method == "PUT":
            cl = cherrypy.request.headers['Content-Length']
            rawbody = cherrypy.request.body.read(int(cl))
            params = json.loads(rawbody)
            return self.update(cid, **params)
        elif method == "DELETE":
            return self.delete(cid, **params)
