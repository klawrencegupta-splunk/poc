const moment = require('moment');
const splunkd = require('splunk_instrumentation/Instrumentation/services/splunkd');
const constants = require('splunk_instrumentation/Instrumentation/constants');

module.exports = {
    /**
     * Returns a unix timestamp by relative values.
     * Note the unix timestamp is recorded in seconds,
     * so to convert to a js Date: `new Date(RETURN_VALUE * 1000)`.
     *
     * Ex: time.timestampAt(-30, 'days')
     *
     * See: `moment().add` from moment.js for calling semantics
     */
    timestampAt(magnitude, unit) {
        return (moment().
            add(magnitude, unit).
            toDate().
            getTime() / 1000);
    },

    /**
     * Accepts an array of splunk relative time modifiers.
     * (see https://docs.splunk.com/Splexicon:Relativetimemodifier)
     * Returns a promise that resolves to an array of Date objects.
     */
    parseSplunkTimeStrings(/* relativeTime... */) {
        const args = Array.prototype.slice.call(arguments);
        return splunkd.get({
            url: splunkd.servicesUrl('/search/timeparser'),
            data: {
                time: args,
                // Specify a format we can easily parse
                output_time_format: constants.DATETIME_FORMAT,
            },
            /* ensures the time array given to data is encoded as multiple time arguments */
            traditional: true,
        }).then((resp) => {
            const result = [];
            args.forEach((k) => {
                const timeString = resp[k];
                // new Date(...) will parse a time string, but is inconsistent among browsers.
                // So, we'll parse out the date fields in a well-defined way.
                const dateMatch = timeString.match(constants.DATE_EXTRACTION_PATTERN);
                const timeMatch = timeString.match(constants.TIME_EXTRACTION_PATTERN);
                const year = dateMatch[1];
                const month = dateMatch[2];
                const day = dateMatch[3];
                const hour = timeMatch[1];
                const min = timeMatch[2];
                const sec = timeMatch[3];
                const date = new Date(year, month - 1, day, hour, min, sec);

                result.push(date);
            });
            return result;
        });
    },

    /**
     * Accepts an object with `earliest` and `latest` properties
     * (that are splunk relative time modifiers)
     * Returns a promise.
     * Resolves to an object with `earliest` and `latest` properties as Date objects.
     * If timeRange.get('earliest') is not provided (or is the empty string) uses the epoch.
     * If timeRange.get('latest') is not provided (or is the empty string) uses 'now'.
     */
    parseTimeRange(timeRange) {
        let earliest = timeRange.earliest;
        let latest = timeRange.latest;

        if (!earliest || earliest.length === 0) {
            earliest = '0';
        }

        if (!latest || latest.length === 0) {
            latest = 'now';
        }

        return this.parseSplunkTimeStrings(earliest, latest).then((results) =>
            ({
                earliest: results[0],
                latest: results[1],
            })
        );
    },

    /**
     * Accepts a Date & an optional separator string (defaults to '-').
     * Returns the YYYY-MM-DD string for the date.
     */
    toYearMonthDayString(date, sep = '-') {
        function pad(num) {
            if (num < 10) {
                return '0' + num;
            }
            return num.toString();
        }

        return date.getFullYear().toString() +
            sep +
            pad(date.getMonth() + 1) +
            sep +
            pad(date.getDate());
    },

    /**
     * Often we're using dates as selected by the user via the time range picker.
     * When a date range is selected, that view generates two timestamps. The latest
     * timestamp, if picking a range of dates, is midnight of the latest day. That
     * timestamp actually parses out to be 00:00:00 of the following day (one day
     * ahead of what we want). So, to be sure we're grabbing the correct day,
     * sometimes we nudge it back a millisecond.
     */
    nudgeMidnightToPreviousDay(date) {
        if (date.toTimeString().indexOf('00:00:00') !== -1) {
            return new Date(date.getTime() - 1);
        }
        return date;
    },
};
