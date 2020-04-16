import logging
import json
import traceback
import cherrypy
import datetime
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
import splunk.appserver.mrsparkle.lib.util as util
import splunk.entity as en
import splunk.rest
from splunk.appserver.mrsparkle.lib.capabilities import Capabilities
import StringIO
from zipfile import ZipFile, ZIP_DEFLATED
from string import Template
from splunk_instrumentation.splunkd import Splunkd
import splunk_instrumentation.packager as packager
import splunk_instrumentation.metrics.instance_profile as instance_profile
from splunk_instrumentation.deployment_id_manager import DeploymentIdManager
from splunk_instrumentation.swa_injection_tool import SwaInitScriptRenderer
from splunk_instrumentation.service_bundle import ServiceBundle
import splunk_instrumentation.client_eligibility as client_eligibility
from splunk.appserver.mrsparkle.lib.htmlinjectiontoolfactory import HtmlInjectionToolFactory

logger = logging.getLogger(__name__)

try:

    swaInitScriptRenderer = SwaInitScriptRenderer(cherrypy)
    HtmlInjectionToolFactory.singleton().register_head_injection_hook(swaInitScriptRenderer)

    def log_errors(fn):
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Exception:
                logger.error('ERROR: In instrumentation_controller.py: ' +
                             traceback.format_exc())
                raise
        return wrapper

    def instrumentation_endpoint(require_authorization=True):
        def decorator(fn):
            @expose_page(must_login=True)
            @log_errors
            def wrapper(self, *args, **kwargs):
                if require_authorization:
                    check_telemetry_authorization(self, *args, **kwargs)
                return fn(self, *args, **kwargs)
            return wrapper

        return decorator

    def check_telemetry_authorization(self, *args, **kwargs):
        self.user = en.getEntity('authentication/users', cherrypy.session['user']['name'])
        if 'edit_telemetry_settings' not in self.user.properties['capabilities']:
            self.deny_access()

    class InstrumentationController(controllers.BaseController, Capabilities):
        """
        This controller implements custom endpoints used by the
        Splunk Metrics application.
        """

        @instrumentation_endpoint(require_authorization=False)
        @route(methods='GET')
        def instrumentation_eligibility(self, **kwargs):
            '''
            Determines whether the UI for the instrumentation app should be visible,
            including the initial opt-in modal and all settings/logs pages.
            This is determined by user capabilities, license type, and server roles.
            '''
            cherrypy.response.headers['Content-Type'] = 'application/json'

            services = ServiceBundle(Splunkd(**self.splunkrc()))

            # If we're not running on a free license (where there are no users),
            # first validate that the user has the requisite capabilities.
            if services.server_info_service.content.get('isFree', '0') != '1':
                user = en.getEntity('authentication/users', cherrypy.session['user']['name'])
                if 'edit_telemetry_settings' not in user.properties['capabilities']:
                    return json.dumps({
                        'is_eligible': False,
                        'reason': 'UNAUTHORIZED'
                    })

            # Now check the server roles, etc
            eligibility = client_eligibility.get_ui_eligibility(services)
            return json.dumps(eligibility)

        @instrumentation_endpoint()
        @route(methods='POST')
        def send_anonymous_usage_data(self, **kwargs):
            return self.send_usage('anonymous', **kwargs)

        @instrumentation_endpoint()
        @route(methods='POST')
        def send_license_usage_data(self, **kwargs):
            return self.send_usage('license', **kwargs)

        def send_usage(self, visibility, **kwargs):
            earliest, latest = self.get_earliest_and_latest(**kwargs)
            events = self.get_events_package(earliest, latest, [visibility])
            if events:
                self.send_events_package(events, earliest, latest, [visibility])
                return json.dumps({'sent_count': len(events)})
            return json.dumps({'sent_count': 0})

        @instrumentation_endpoint()
        @route(methods='GET')
        def anonymous_usage_data(self, **kwargs):
            earliest, latest = self.get_earliest_and_latest(**kwargs)
            if self.isMoreThanOneYear(earliest, latest):
                raise cherrypy.HTTPError(code=403, message="Date range must be less than 1 year.")
            zip_file_name, json_file_name = self.get_file_name(earliest, latest, 'Diagnostic')

            cherrypy.response.headers['Content-Disposition'] = ('attachment; filename="%s"' % (zip_file_name))
            cherrypy.response.headers['Content-Type'] = 'application/zip'

            value = self.get_file_value(earliest, latest, ['anonymous'])
            temp_value = self.write_to_string(json_file_name, value)
            if temp_value:
                return temp_value
            raise cherrypy.HTTPError(403)

        @instrumentation_endpoint()
        @route(methods='GET')
        def license_usage_data(self, **kwargs):
            earliest, latest = self.get_earliest_and_latest(**kwargs)
            if self.isMoreThanOneYear(earliest, latest):
                raise cherrypy.HTTPError(code=403, message="Date range must be less than 1 year.")
            zip_file_name, json_file_name = self.get_file_name(earliest, latest, 'License Usage')

            cherrypy.response.headers['Content-Disposition'] = ('attachment; filename=%s' % zip_file_name)
            cherrypy.response.headers['Content-Type'] = 'application/zip'

            value = self.get_file_value(earliest, latest, ['license'])
            temp_value = self.write_to_string(json_file_name, value)
            if temp_value:
                return temp_value
            raise cherrypy.HTTPError(403)

        def get_file_name(self, earliest, latest, data_type, file_type=['zip', 'json']):
            filename = Template('%s Data - %s to %s.$filename' % (
                data_type,
                ('%d.%02d.%02d' % (earliest.year, earliest.month, earliest.day)),
                ('%d.%02d.%02d' % (latest.year, latest.month, latest.day))
            ))
            return [filename.substitute(filename=ft) for ft in file_type]

        def write_to_string(self, json_file_name, value):
            temp = StringIO.StringIO()
            with ZipFile(temp, 'w', ZIP_DEFLATED) as myzip:
                myzip.writestr(json_file_name, value)
            return temp.getvalue()

        def get_file_value(self, earliest, latest, visibility):
            _packager = packager.Packager(splunkrc=self.splunkrc())
            _instance_profile = instance_profile.get_instance_profile(splunkrc=self.splunkrc())
            deployment_id = _instance_profile.get_deployment_id()
            transaction_id = _packager.get_transactionID()
            value = self.get_events_package(earliest, latest, visibility, forExport=True)

            ret_value = {
                "deploymentID": deployment_id,
                "transactionID": transaction_id,
                "data": value}
            return json.dumps(ret_value)

        def get_events_package(self, earliest, latest, visibility, forExport=False):
            _packager = packager.Packager(splunkrc=self.splunkrc())
            return _packager.build_package(earliest, latest, visibility, forExport)

        def send_events_package(self, package, earliest, latest, visibility):
            _packager = packager.Packager(splunkrc=self.splunkrc())
            _packager.manual_send_package(package, earliest, latest, visibility)

        def get_earliest_and_latest(self, **kwargs):
            self.assert_earliest_and_latest_provided(**kwargs)
            return self.timestamp_to_internal_repr(kwargs.get('earliest'), kwargs.get('latest'))

        def assert_earliest_and_latest_provided(self, **kwargs):
            if not kwargs.get('earliest') or not kwargs.get('latest'):
                raise Exception("earliest and latest query params are required")

        def timestamp_to_internal_repr(self, *args):
            result = []
            for arg in args:
                # the arguments passed in are sting with format of <year>-<month>-<day> ex 2016-3-4
                # the conversion is done by hand instead of strptime because of the lack of padding
                # on date and month
                date_array = arg.split("-")
                result.append(datetime.date(year=int(date_array[0]), month=int(date_array[1]), day=int(date_array[2])))

            if len(result) == 1:
                return result[0]
            else:
                return result

        def splunkrc(self):
            return {
                'token': cherrypy.session['sessionKey'],
                'server_uri': splunk.rest.makeSplunkdUri()
            }

        def isMoreThanOneYear(self, earliest, latest):
            copyEarliest = earliest.replace(year=earliest.year + 1)
            if latest > copyEarliest:
                return True
            return False

except Exception, ex:
    logger.error('ERROR while loading instrumentation_controller.py: ' + traceback.format_exc())
    raise
