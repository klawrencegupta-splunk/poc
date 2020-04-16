const _ = require('underscore');
const constants = module.exports = {};

/**
 * Generates SPL of an instrumentation saved search.
 * @param savedSearchName: Name of saved search (Automatically appends instrumentation to name)
 * @param searchParams: Array of addition params. (Optional)
 * @returns String: SPL of a given instrumentation saved search.
 */
function _getSavedSearch(savedSearchName, searchParams) {
    let searchParamStr = '';
    if (searchParams && searchParams.length) {
        searchParamStr = ` ${searchParams.join(' ')}`;
    } else {
        searchParamStr = '';
    }
    return `| savedsearch instrumentation.${savedSearchName} ${searchParamStr}`;
}

constants.EPOCH_DATE = new Date(1971, 0, 1);

constants.DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S';
constants.DATE_EXTRACTION_PATTERN = /(\d{4})-(\d{1,2})-(\d{1,2})/;
constants.TIME_EXTRACTION_PATTERN = /(\d{1,2}):(\d{1,2}):(\d{1,2})/;

constants.DATA_TYPES = {
    ANONYMOUS: 'ANONYMOUS',
    LICENSE: 'LICENSE',
};

constants.SEARCH_KEEP_ALIVE_INTERVAL = 30000;

constants.ALL_DATA_TYPES = Object.keys(constants.DATA_TYPES);

constants.SEARCH_PAGE_URL = '/app/splunk_instrumentation/search';

constants.DEFAULT_SERVER_ERROR =
    _('Error communicating with Splunk. Please check your network connection and try again.').t();

constants.TELEMETRY_CAPABILITY_NAME = 'edit_telemetry_settings';

constants.APP_NAME = 'splunk_instrumentation';

constants.INSTRUMENTATION_CONTROLLER_URL =
    '/custom/splunk_instrumentation/instrumentation_controller';

constants.SPLUNKD_TELEMETRY_ROOT_URL =
    '/splunkd/__raw/servicesNS/nobody/splunk_instrumentation/admin/telemetry';

constants.ANY_TELEMETRY_EVENT = _getSavedSearch('anyEvent');

constants.ANONYMIZED_TELEMETRY_EVENTS_BY_TIME_QUERY = _getSavedSearch('anonymized.eventsByTime');

constants.LICENSE_TELEMETRY_EVENTS_QUERY = _getSavedSearch('licenseUsage');

constants.DATA_REPORTING_QUERY_TEMPLATE =
    _getSavedSearch('reporting', ['visibility=$VISIBILITY']);

constants.DATA_REPORTING_ERROR_COUNT_QUERY = _getSavedSearch('reportingErrorCount');

(() => {
    const viewDataReportingErrorsUrlTemplate =
        _getSavedSearch('reporting.errors', ['visibility=$VISIBILITY']);

    const urls = [];
    ['anonymous', 'license'].forEach((visibility) => {
        urls.push(
            `${
                constants.SEARCH_PAGE_URL
            }?q=${
                encodeURIComponent(viewDataReportingErrorsUrlTemplate.
                    replace('$VISIBILITY', visibility))
            }&earliest=${
                encodeURIComponent('-30d@d')
            }`
        );
    });

    constants.VIEW_30DAY_ANONYMOUS_REPORTING_ERRORS_URL = urls[0];
    constants.VIEW_30DAY_LICENSE_REPORTING_ERRORS_URL = urls[1];
})();

constants.LAST_REPORT_QUERY = _getSavedSearch('lastSent');

constants.DATA_EXPORT_URL_TEMPLATE =
    '/$VISIBILITY_usage_data?earliest=$EARLIEST&latest=$LATEST';

constants.DATA_SEND_URL_TEMPLATE =
    '/send_$VISIBILITY_usage_data?earliest=$EARLIEST&latest=$LATEST';

constants.FIRST_ANONYMIZED_DATA_EVENT_QUERY_TEMPLATE =
    _getSavedSearch('anonymized.firstEvent',
            ['beginDate=$BEGIN_DATE', 'endDate=$END_DATE']);

constants.FIRST_LICENSE_DATA_EVENT_QUERY_TEMPLATE =
    _getSavedSearch('license.firstEvent', ['beginDate=$BEGIN_DATE', 'endDate=$END_DATE']);

constants.DATA_REPORTING_VALIDATION = {
    ACTION: {
        SEND: 'send',
        EXPORT: 'export',
    },
    ERROR_MESSAGE: {
        NO_DATA: {
            CODE: 1,
            MESSAGE: _('No data available for selected time range').t(),
        },
        MORE_THAN_ONE_YEAR: {
            CODE: 2,
            MESSAGE: _('Date ranges must be less than 1 year').t(),
        },
        DEFAULT: {
            CODE: 0,
            MESSAGE: constants.DEFAULT_SERVER_ERROR,
            DETAILS: 'unknown error',
        },
    },
};

constants.SEARCH_OPT = {
    owner: '-',
    app: 'splunk_instrumentation',
};

constants.TRANSIENT_SEARCH_JOB_TIMEOUT = 10;
