var _ = require('underscore');

var constants = module.exports = {};

constants.EPOCH_DATE = new Date(1971, 0, 1);

constants.DATA_TYPES = {
    ANONYMOUS: 'ANONYMOUS',
    LICENSE: 'LICENSE',
};

constants.SEARCH_KEEP_ALIVE_INTERVAL = 30000;

constants.ALL_DATA_TYPES = Object.keys(constants.DATA_TYPES);

constants.SEARCH_PAGE_URL = '/app/splunk_instrumentation/search';

constants.DEFAULT_SERVER_ERROR =
    _("Error communicating with Splunk. Please check your network connection and try again.").t();

constants.TELEMETRY_CAPABILITY_NAME = 'edit_telemetry_settings';

constants.APP_NAME = 'splunk_instrumentation';

constants.INSTRUMENTATION_CONTROLLER_URL =
    '/custom/splunk_instrumentation/instrumentation_controller';

constants.SPLUNKD_TELEMETRY_ROOT_URL =
    '/splunkd/__raw/servicesNS/nobody/splunk_instrumentation/admin/telemetry';

constants.ANY_TELEMETRY_EVENT =
    'search index=_telemetry | head 1';

constants.ANONYMIZED_TELEMETRY_EVENTS_BY_TIME_QUERY =
    'index=_telemetry sourcetype=splunk_telemetry visibility=*anonymous* ' +
    '| append [| savedsearch instrumentation.licenseUsage]';

constants.LICENSE_TELEMETRY_EVENTS_QUERY =
    '| savedsearch instrumentation.licenseUsage';

constants.DATA_REPORTING_QUERY_TEMPLATE =
    'search index=_telemetry sourcetype=splunk_telemetry_log | fields _raw | spath | search (status=success OR status=failed) visibility=*$VISIBILITY* ';

constants.DATA_REPORTING_ERROR_COUNT_QUERY =
    '| savedsearch instrumentation.reportingErrors';

(function () {
    var viewDataReportingErrorsUrlTemplate =
        'search index=_telemetry sourcetype=splunk_telemetry_log status=failed visibility=*$VISIBILITY*';

    var urls = [];
    ['anonymous', 'license'].forEach(function (visibility) {
        urls.push(
            constants.SEARCH_PAGE_URL +
            '?q=' +
            encodeURIComponent(viewDataReportingErrorsUrlTemplate.
                replace('$VISIBILITY', visibility)) +
            '&earliest=' +
            encodeURIComponent('-30d@d')
        );
    });

    constants.VIEW_30DAY_ANONYMOUS_REPORTING_ERRORS_URL = urls[0];
    constants.VIEW_30DAY_LICENSE_REPORTING_ERRORS_URL = urls[1];
}());

constants.LAST_REPORT_QUERY =
    '| savedsearch instrumentation.lastSent';

constants.DATA_EXPORT_URL_TEMPLATE =
    '/$VISIBILITY_usage_data?earliest=$EARLIEST&latest=$LATEST';

constants.DATA_SEND_URL_TEMPLATE =
    '/send_$VISIBILITY_usage_data?earliest=$EARLIEST&latest=$LATEST';

constants.FIRST_ANONYMIZED_DATA_EVENT_QUERY_TEMPLATE =
    'search index=_telemetry sourcetype=splunk_telemetry visibility=*anonymous* ' +
    '| append [savedsearch instrumentation.licenseUsage] ' +
    '| where date >= "$BEGIN_DATE" AND date <= "$END_DATE" ' +
    '| head 1'

constants.FIRST_LICENSE_DATA_EVENT_QUERY_TEMPLATE =
    '| savedsearch instrumentation.licenseUsage ' + 
    '| where date >= "$BEGIN_DATE" AND date <= "$END_DATE" ' +
    '| head 1';

constants.DATA_REPORTING_VALIDATION = {
    ACTION: {
        SEND: 'send',
        EXPORT: 'export'
    },
    ERROR_MESSAGE: {
        NO_DATA: {
            CODE : 1,
            MESSAGE : _("No data available for selected time range").t(),
        },
        MORE_THAN_ONE_YEAR: {
            CODE : 2,
            MESSAGE : _("Date ranges must be less than 1 year").t(),
        },
        DEFAULT: {
            CODE: 0,
            MESSAGE: constants.DEFAULT_SERVER_ERROR,
            DETAILS: "unknown error"
        }
    }
};

constants.SEARCH_OPT = {
    owner: '-',
    app: 'splunk_instrumentation'
};

constants.TRANSIENT_SEARCH_JOB_TIMEOUT = 10;
