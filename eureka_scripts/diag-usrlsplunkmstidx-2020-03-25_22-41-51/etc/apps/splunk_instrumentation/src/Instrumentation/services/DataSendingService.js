var _ = require('underscore'),
    $ = require('jquery'),
    constants = require('Instrumentation/constants'),
    environment = require('Instrumentation/services/environment');
    time = require('Instrumentation/services/time'),
    splunkd = require('Instrumentation/services/splunkd');


function DataSendingService() {};

DataSendingService.prototype = {
    get rootUrl() {
        var application = environment.get('application'),
            root = application.get('root');
        return (root ? '/' + root : '') + '/' + application.get('locale') + constants.INSTRUMENTATION_CONTROLLER_URL;
    },

    makeSendURL: function (dates, visibility) {
        return this.rootUrl + constants.DATA_SEND_URL_TEMPLATE
            .replace('$EARLIEST', dates.earliest.getTime() / 1000)
            .replace('$LATEST', dates.latest.getTime() / 1000)
            .replace('$VISIBILITY', visibility.toLowerCase());
    },

    makeExportURL: function (dates, visibility) {
        return this.rootUrl + constants.DATA_EXPORT_URL_TEMPLATE
            .replace('$EARLIEST', dates.earliest.getTime() / 1000)
            .replace('$LATEST', dates.latest.getTime() / 1000)
            .replace('$VISIBILITY', visibility.toLowerCase());
    },

    /**
     * Parameters:
     * - timeRange: models.shared.TimeRange
     */
    sendAnonymousData: function (timeRange) {
        return this.sendData(timeRange, constants.DATA_TYPES['ANONYMOUS']);
    },

    /**
     * Parameters:
     * - timeRange: models.shared.TimeRange
     */
    sendLicenseData: function (timeRange) {
        return this.sendData(timeRange, constants.DATA_TYPES['LICENSE']);
    },

    sendData: function (timeRange, visibility) {
        var context = {};
        return time.parseTimeRange(timeRange.attributes).
            then(function (dates) {
                context.dates = this.normalizeTimeRangeDates(dates);
                return $.post(this.makeSendURL(context.dates, visibility));
            }.bind(this)).
            then(function (resp) {
                if (JSON.parse(resp).sent_count == 0) {
                    var def = $.Deferred();
                    def.reject(constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE['NO_DATA']);
                    return def;
                }
            });
    },

    /**
     * Parameters:
     * - timeRange: models.shared.TimeRange
     */
    exportAnonymousData: function (timeRange) {
        return this.exportData(timeRange, constants.DATA_TYPES['ANONYMOUS']);
    },

    /**
     * Parameters:
     * - timeRange: models.shared.TimeRange
     */
    exportLicenseData: function (timeRange) {
        return this.exportData(timeRange, constants.DATA_TYPES['LICENSE']);
    },

    exportData: function (timeRange, visibility) {
        // Triggers a download, without changing the current location,
        // as long as the server sets the "Content-Disposition: attachment" header.
        var context = {},
            def = $.Deferred();

        time.parseTimeRange(timeRange.attributes).
            then(function (dates) {
                context.dates = this.normalizeTimeRangeDates(dates);
                if (this.isMoreThanOneYear(dates)) {
                    // returned an Error object because jQuery Deffered does not
                    // catch exception
                    var message = constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE['MORE_THAN_ONE_YEAR'];
                    def.reject(message);
                }
                return this.checkForTelemetryEventsWithDateInRange(context.dates, visibility);
            }.bind(this)).then(function () {
                if (def.state()!=='rejected') {
                    window.location = this.makeExportURL(context.dates, visibility);
                }
            }.bind(this)).done(function () {
                if (def.state()==='pending') {
                    def.resolve.apply(def,arguments);
                }
            }).fail(function () {
                if (def.state()==='pending') {
                    def.reject.apply(def, arguments);
                }
            });

        return def;

    },

    /**
     * Parameters:
     * - dates: Object with `earliest` and `latest` properties as Date objects.
     * - dataType: A member of constants.DATA_TYPES
     */
    checkForTelemetryEventsWithDateInRange: function (dates, dataType) {
        var def = $.Deferred(),
            query;


        dates = this.normalizeTimeRangeDates(dates);

        var earliestDate = time.toYearMonthDayString(dates.earliest),
            latestDate = time.toYearMonthDayString(dates.latest);

        var template = (dataType == constants.DATA_TYPES.ANONYMOUS) ?
            constants.FIRST_ANONYMIZED_DATA_EVENT_QUERY_TEMPLATE :
            constants.FIRST_LICENSE_DATA_EVENT_QUERY_TEMPLATE;

        query = template.
            replace(/\$BEGIN_DATE/g, earliestDate).
            replace(/\$END_DATE/g, latestDate);

        splunkd.search(query, _.extend({search: {timeout: constants.TRANSIENT_SEARCH_JOB_TIMEOUT}}, constants.SEARCH_OPT)).
            then(function (searchData) {
                var count = searchData.outcome.results.length;
                if (count === 0) {
                    def.reject(constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE['NO_DATA']);
                }
                else {
                    def.resolve();
                }
            }).fail(function (err) {
                var message = constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE['DEFAULT'];
                message['DETAILS'] = err;
                def.reject(message);
            });

        return def;
    },

    normalizeTimeRangeDates: function (_dates) {
        // Shallow copy
        var dates = _.extend({}, _dates);

        // The date of the epoch time given from the time range picker
        // may actually occur on 1969-06-31 or 1970-01-01 depending on local time.
        // Some splunk search commands return empty results when the earliest time
        // is set before 1971-01-01, so we'll set a lower bound here.
        if (dates.earliest < constants.EPOCH_DATE) {
            dates.earliest = constants.EPOCH_DATE;
        }

        // - The date range picker will select midnight (24:00:00)
        //   of the "lastest" date.
        // - The Date object comes out to be the next day (@ 00:00:00).
        // - We select events by inclusive date (not by time), so to ensure
        //   we're not including an extra day on the end, we'll have to nudge
        //   any midnight latest times back to the previous day.
        dates.latest = time.nudgeMidnightToPreviousDay(dates.latest);

        return dates;
    },

    isMoreThanOneYear: function (_dates) {
        // Shallow copy
        var earliest = new Date(_dates.earliest.getTime()),
            latest = new Date(_dates.latest.getTime());

        // Add one year to earliest, and check if its bigger than latest.
        earliest.setFullYear(earliest.getFullYear() + 1);

        if (latest.getTime() > earliest.getTime()) {
            return true;
        }

        return false;

    }
};

module.exports = DataSendingService;
