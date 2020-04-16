const _ = require('underscore');
const $ = require('jquery');
const constants = require('splunk_instrumentation/Instrumentation/constants');
const time = require('splunk_instrumentation/Instrumentation/services/time');
const splunkd = require('splunk_instrumentation/Instrumentation/services/splunkd');

function DataSendingService() {}

DataSendingService.prototype = {
    get rootUrl() {
        return splunkd.routes.encodeRoot(constants.INSTRUMENTATION_CONTROLLER_URL);
    },

    _getDate(date) {
        return `${date.getFullYear()}-${date.getMonth() + 1}-${date.getDate()}`;
    },
    _makeURL(dates, visibility, template) {
        return this.rootUrl + template
                .replace('$EARLIEST', this._getDate(dates.earliest))
                .replace('$LATEST', this._getDate(dates.latest))
                .replace('$VISIBILITY', visibility.toLowerCase());
    },
    makeSendURL(dates, visibility) {
        return this._makeURL(dates, visibility, constants.DATA_SEND_URL_TEMPLATE);
    },

    makeExportURL(dates, visibility) {
        return this._makeURL(dates, visibility, constants.DATA_EXPORT_URL_TEMPLATE);
    },

    /**
     * Parameters:
     * - timeRange: models.shared.TimeRange
     */
    sendAnonymousData(timeRange) {
        return this.sendData(timeRange, constants.DATA_TYPES.ANONYMOUS);
    },

    /**
     * Parameters:
     * - timeRange: models.shared.TimeRange
     */
    sendLicenseData(timeRange) {
        return this.sendData(timeRange, constants.DATA_TYPES.LICENSE);
    },

    sendData(timeRange, visibility) {
        const context = {};
        return time.parseTimeRange(timeRange.attributes).
            then((dates) => {
                context.dates = this.normalizeTimeRangeDates(dates);
                return $.post(this.makeSendURL(context.dates, visibility));
            }).
            then((resp) => {
                let parsedResp = resp;
                if (typeof resp !== 'object') {
                    parsedResp = JSON.parse(resp);
                }
                if (parseInt(parsedResp.sent_count, 10) === 0) {
                    const def = new $.Deferred();
                    def.reject(constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE.NO_DATA);
                    return def;
                }
                return parsedResp;
            });
    },

    /**
     * Parameters:
     * - timeRange: models.shared.TimeRange
     */
    exportAnonymousData(timeRange) {
        return this.exportData(timeRange, constants.DATA_TYPES.ANONYMOUS);
    },

    /**
     * Parameters:
     * - timeRange: models.shared.TimeRange
     */
    exportLicenseData(timeRange) {
        return this.exportData(timeRange, constants.DATA_TYPES.LICENSE);
    },

    exportData(timeRange, visibility) {
        // Triggers a download, without changing the current location,
        // as long as the server sets the "Content-Disposition: attachment" header.
        const context = {};
        const def = new $.Deferred();

        time.parseTimeRange(timeRange.attributes).
            then((dates) => {
                context.dates = this.normalizeTimeRangeDates(dates);
                if (this.isMoreThanOneYear(dates)) {
                    // returned an Error object because jQuery Deffered does not
                    // catch exception
                    const message = constants.DATA_REPORTING_VALIDATION.
                        ERROR_MESSAGE.MORE_THAN_ONE_YEAR;
                    def.reject(message);
                }
                return this.checkForTelemetryEventsWithDateInRange(context.dates, visibility);
            }).
            then(() => {
                if (def.state() !== 'rejected') {
                    window.location = this.makeExportURL(context.dates, visibility);
                }
            }).
            done((...args) => {
                if (def.state() === 'pending') {
                    def.resolve.apply(def, args);
                }
            }).
            fail((...args) => {
                if (def.state() === 'pending') {
                    def.reject.apply(def, args);
                }
            });

        return def;
    },

    /**
     * Parameters:
     * - dates: Object with `earliest` and `latest` properties as Date objects.
     * - dataType: A member of constants.DATA_TYPES
     */
    checkForTelemetryEventsWithDateInRange(dates, dataType) {
        const def = new $.Deferred();

        dates = this.normalizeTimeRangeDates(dates);

        const earliestDate = time.toYearMonthDayString(dates.earliest);
        const latestDate = time.toYearMonthDayString(dates.latest);

        const template = (dataType === constants.DATA_TYPES.ANONYMOUS) ?
            constants.FIRST_ANONYMIZED_DATA_EVENT_QUERY_TEMPLATE :
            constants.FIRST_LICENSE_DATA_EVENT_QUERY_TEMPLATE;

        const query = template.
            replace(/\$BEGIN_DATE/g, earliestDate).
            replace(/\$END_DATE/g, latestDate);

        splunkd.search(query,
            _.extend(
                {search: {timeout: constants.TRANSIENT_SEARCH_JOB_TIMEOUT}},
                constants.SEARCH_OPT)
        ).then(function (searchData) {
            const count = searchData.outcome.results.length;
            if (count === 0) {
                def.reject(constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE.NO_DATA);
            }
            else {
                def.resolve();
            }
        }).fail((err) => {
            const message = constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE.DEFAULT;
            message.DETAILS = err;
            def.reject(message);
        });

        return def;
    },

    normalizeTimeRangeDates(_dates) {
        // Shallow copy
        const dates = _.extend({}, _dates);

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

    isMoreThanOneYear(_dates) {
        // Shallow copy
        const earliest = new Date(_dates.earliest.getTime());
        const latest = new Date(_dates.latest.getTime());

        // Add one year to earliest, and check if its bigger than latest.
        earliest.setFullYear(earliest.getFullYear() + 1);

        if (latest.getTime() > earliest.getTime()) {
            return true;
        }

        return false;
    },
};

module.exports = DataSendingService;
