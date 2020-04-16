const $ = require('jquery');
const _ = require('underscore');
const constants = require('splunk_instrumentation/Instrumentation/constants');
const splunkd = require('splunk_instrumentation/Instrumentation/services/splunkd');
const SplunkUtil = require('splunk.util');

module.exports = class InstrumentationService {
    constructor() {
        // We'll cache this the first time we grab the telemetry conf file data
        this.optInVersion = null;
    }

    /**
     * Determines whether instrumentation (the feature as a whole)
     * is eligible for this user & server.
     * Returns a deferred that resolves to the parsed body of the
     * instrumentation_eligibility endpoint.
     */
    getInstrumentationEligibility(root) {
        const path = SplunkUtil.make_url(constants.INSTRUMENTATION_CONTROLLER_URL, 'instrumentation_eligibility');
        return $.get(path).then(
            // Seems redundant, but omits the other arguments that jquery
            // otherwised passes through .then & .done, making use of
            // this function with things like $.when a little cleaner.
            (resp) => resp
        );
    }

    /**
     * Used to read the properties in the general stanza.
     * Returns a promise that resolves to the content of the stanza or rejects with the xhr object.
     */
    getGeneralStanza() {
        return splunkd.get(this.telemetryUrl('/general')).then((resp) => {
            // This value won't be changing between page loads (since it
            // is only updated when installing a new splunk version).
            // So, we'll cache it asap to avoid an additional round-trip later.
            if (!this.optInVersion) {
                this.optInVersion = resp.entry[0].content.optInVersion;
            }
            return resp;
        });
    }

    /**
     * Used to update the properties in the general stanza.
     * Accepts a `properties` object, with key/value pairs to be set in the stanza.
     * Returns a promise that resolves to the content of the stanza or rejects with the xhr object.
     *
     * Using this method (as opposed to a simple post) ensures that the opt-in modal is no
     * longer displayed on login once a setting is updated explicitly by a user.
     */
    updateGeneralStanza(properties) {
        function updateGeneralStanzaInternal(optInVersion) {
            return splunkd.post(this.telemetryUrl('/general'), {}, _.defaults(
                properties,
                {
                    showOptInModal: false,
                    optInVersionAcknowledged: optInVersion,
                }
            )).then(resp => resp);
        }

        if (this.optInVersion) {
            return updateGeneralStanzaInternal.call(this, this.optInVersion);
        } else {
            return this.getGeneralStanza().then((general) => {
                return updateGeneralStanzaInternal.call(this, general.entry[0].content.optInVersion);
            });
        }
    }

    get30DayReportingErrorCounts() {
        return splunkd.search(
            constants.DATA_REPORTING_ERROR_COUNT_QUERY,
            this.getSearchOptions({
                search: {
                    earliest_time: '-30d@d',
                    timeout: constants.TRANSIENT_SEARCH_JOB_TIMEOUT,
                },
            })
        ).then((searchData) => {
            const stats = searchData.outcome.results[0];
            if (stats) {
                return {
                    anonymous_errors: parseInt(stats.anonymous_errors, 10),
                    license_errors: parseInt(stats.license_errors, 10),
                };
            }
            return {
                anonymous_errors: 0,
                license_errors: 0,
            };
        });
    }

    getLastSuccessfulReportTimes() {
        return splunkd.search(
            constants.LAST_REPORT_QUERY,
            this.getSearchOptions({ search: { timeout: 10 } })
        ).then((searchData) => {
            const results = searchData.outcome.results;
            return {
                latest_anonymous_send_time: (results[0] && results[0].latest_anonymous_send_time) ?
                    new Date(parseInt(results[0].latest_anonymous_send_time, 10) * 1000) :
                    null,
                latest_license_send_time: (results[0] && results[0].latest_license_send_time) ?
                    new Date(parseInt(results[0].latest_license_send_time, 10) * 1000) :
                    null,
            };
        });
    }

    getAnonymousReportingLogs(earliest, latest, resultOptions) {
        return this.getReportingLogs(earliest, latest, 'anonymous', resultOptions);
    }

    getLicenseReportingLogs(earliest, latest, resultOptions) {
        return this.getReportingLogs(earliest, latest, 'license', resultOptions);
    }

    getReportingLogs(earliest, latest, visibility, resultOptions = {}) {
        const searchOptions = {};
        const query = constants.DATA_REPORTING_QUERY_TEMPLATE.replace('$VISIBILITY', visibility);

        if (!resultOptions.count) {
            resultOptions.count = 0;
        }

        searchOptions.earliest_time = earliest;
        searchOptions.latest_time = latest;

        // See: SPL-127100
        // https://answers.splunk.com/answers/128761/programmatically-setting-search-mode-to-fast.html
        searchOptions.adhoc_search_level = 'fast';

        return splunkd.search(query,
                _.extend({ search: searchOptions, results: resultOptions }, constants.SEARCH_OPT));
    }

    telemetryUrl(endpoint) {
        return splunkd.servicesNsUrl('nobody', constants.APP_NAME, '/admin/telemetry' +
            (endpoint && endpoint[0] === '/' ? '' : '/') +
            endpoint
        );
    }

    getSearchOptions(opt = {}) {
        return _.defaults(opt, constants.SEARCH_OPT);
    }
};

