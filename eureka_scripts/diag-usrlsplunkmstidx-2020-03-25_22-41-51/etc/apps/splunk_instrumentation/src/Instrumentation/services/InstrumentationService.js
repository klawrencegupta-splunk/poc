var $ = require('jquery'),
    _ = require('underscore'),
    constants = require('Instrumentation/constants'),
    splunkd = require('Instrumentation/services/splunkd'),
    environment = require('Instrumentation/services/environment'),
    moment = require('moment'),
    time = require('Instrumentation/services/time');

var _class = function InstrumentationService() {};
var _proto = _class.prototype = {};

/**
 * Determines whether instrumentation (the feature as a whole) is eligible for this user & server.
 * Returns a deferred that resolves to the parsed body of the instrumentation_eligibility endpoint.
 */
_proto.getInstrumentationEligibility = function (root) {
    return $.get((root ? '/' + root : '') + constants.INSTRUMENTATION_CONTROLLER_URL + '/instrumentation_eligibility').then(
        function (resp) {
            // Seems redundant, but omits the other arguments that jquery
            // otherwised passes through .then & .done, making use of
            // this function with things like $.when a little cleaner.
            return resp;
        }
    );
};

/**
 * Used to read the properties in the general stanza.
 * Returns a promise that resolves to the content of the stanza or rejects with the xhr object.
 */
_proto.getGeneralStanza = function () {
    return splunkd.get(this.telemetryUrl('/general')).then(function (resp) { return resp; });
};

/**
 * Used to update the properties in the general stanza.
 * Accepts a `properties` object, with key/value pairs to be set in the stanza.
 * Returns a promise that resolves to the content of the stanza or rejects with the xhr object.
 *
 * Using this method (as opposed to a simple post) ensures that the opt-in modal is no
 * longer displayed on login once a setting is updated explicitly by a user.
 */
_proto.updateGeneralStanza = function (properties) {
    return splunkd.post(this.telemetryUrl('/general'), {}, _.defaults(
        properties,
        { showOptInModal: false }
    ));
};

_proto.get30DayReportingErrorCounts = function () {
    return splunkd.search(
        constants.DATA_REPORTING_ERROR_COUNT_QUERY,
        this.getSearchOptions({search: {earliest_time: '-30d@d', timeout: constants.TRANSIENT_SEARCH_JOB_TIMEOUT}})
    ).then(function (searchData) {
         var stats = searchData.outcome.results[0];
         if (stats) {
             return {
                 anonymous_errors: parseInt(stats.anonymous_errors, 10),
                 license_errors: parseInt(stats.license_errors, 10),
             };
         } else {
             return {
                 anonymous_errors: 0,
                 license_errors: 0,
             };
         }
    });
};

_proto.getLastSuccessfulReportTimes = function () {
    return splunkd.search(
        constants.LAST_REPORT_QUERY,
        this.getSearchOptions({search: {timeout: 10}})
    ).then(function (searchData) {
        var results = searchData.outcome.results;
        return {
            latest_anonymous_send_time: (results[0] && results[0].latest_anonymous_send_time) ?
                new Date(parseInt(results[0].latest_anonymous_send_time, 10) * 1000) :
                null,
            latest_license_send_time: (results[0] && results[0].latest_license_send_time) ?
                new Date(parseInt(results[0].latest_license_send_time, 10) * 1000) :
                null
        };
    });
};

_proto.getAnonymousReportingLogs = function (earliest, latest, resultOptions) {
    return this.getReportingLogs(earliest, latest, 'anonymous', resultOptions);
};

_proto.getLicenseReportingLogs = function (earliest, latest, resultOptions) {
    return this.getReportingLogs(earliest, latest, 'license', resultOptions);
};

_proto.getReportingLogs = function (earliest, latest, visibility, resultOptions) {
    var searchOptions = {},
        query = constants.DATA_REPORTING_QUERY_TEMPLATE.replace('$VISIBILITY', visibility);

    resultOptions = resultOptions || {};
    if (!resultOptions.count) {
        resultOptions.count = 0;
    }

    searchOptions.earliest_time = earliest;
    searchOptions.latest_time = latest;
    
    // See: SPL-127100, https://answers.splunk.com/answers/128761/programmatically-setting-search-mode-to-fast.html
    searchOptions.adhoc_search_level = "fast";

    return splunkd.search(query, _.extend({search: searchOptions, results: resultOptions}, constants.SEARCH_OPT));
};

_proto.telemetryUrl = function (endpoint) {
    return splunkd.servicesNsUrl('nobody', constants.APP_NAME, '/admin/telemetry' +
        (endpoint && endpoint[0] == '/' ? '' : '/') +
        endpoint
    );
};

_proto.getSearchOptions = function (opt) {
    opt = opt || {};
    return _.defaults(opt, constants.SEARCH_OPT);
};

module.exports = _class;
